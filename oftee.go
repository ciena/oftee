// OFTEE command to start a OpenFlow tee proxy. This command parses the
// environment for configuration information and then starts a processing
// loop for OpenFlow messages.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ciena/oftee/api"
	"github.com/ciena/oftee/connections"
	"github.com/ciena/oftee/criteria"
	"github.com/ciena/oftee/injector"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kelseyhightower/envconfig"
	of "github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
)

const (
	// ReadBufferSize Buffer size when reading
	ReadBufferSize = 2048

	// Supported and future supported URL schemes

	// SchemeTCP prefex for TCP URI scheme
	SchemeTCP = "tcp"

	// SchemeHTTP prefex for HTTP URI scheme
	SchemeHTTP = "http"

	// SchemeKafka prefex for Kafka URI scheme
	SchemeKafka = "kafka"

	// Supported end point configuration terms

	// TermAction term used in match / action to depict an action
	TermAction = "action"

	// TermDLType term use in match / action to depict a dl_type match
	TermDLType = "dl_type"
)

// App Maintains the application configuration and runtime state
type App struct {
	ShowHelp         bool     `envconfig:"HELP" default:"false" desc:"show this message"`
	ListenOn         string   `envconfig:"LISTEN_ON" default:":8000" required:"true" desc:"connection on which to listen for an open flow device"`
	APIOn            string   `envconfig:"API_ON" default:":8002" required:"true" desc:"port on which to listen to accept API requests"`
	ProxyTo          string   `envconfig:"PROXY_TO" default:":8001" required:"true" desc:"connection on which to attach to an SDN controller"`
	TeeTo            []string `envconfig:"TEE_TO" desc:"list of connections on which tee packet in messages"`
	TeeRawPackets    bool     `envconfig:"TEE_RAW" default:"false" desc:"only tee raw packets to the client, openflow headers not included"`
	LogLevel         string   `envconfig:"LOG_LEVEL" default:"debug" desc:"logging level"`
	ShareConnections bool     `envconfig:"SHARE_CONNECTIONS" default:"true" desc:"use shared connections to outbound end points"`

	listener  net.Listener
	endpoints connections.Endpoints
	api       *api.API
}

// OpenFlowContext provides context for OF packet in messages
type OpenFlowContext struct {
	DatapathID uint64
	Port       uint32
}

func (c *OpenFlowContext) String() string {
	return fmt.Sprintf("[0x%016x, 0x%04x]", c.DatapathID, c.Port)
}

// Len returns the length of the OpenFlowContext
func (c *OpenFlowContext) Len() uint16 {
	return 12
}

// WriteTo writes the open flow context to the provided writer
func (c *OpenFlowContext) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf, c.DatapathID)
	binary.BigEndian.PutUint32(buf[8:], c.Port)
	val, err := w.Write(buf)
	return int64(val), err
}

// Why or why does Go not have a simply int minimum function, ok, i get it,
// proverb A little copying is better than a little dependency, but this could
// be part of a standard lib
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (app *App) cleanup() {
}

func (app *App) removeInjector(inject injector.Injector) {
	app.api.DPIDMappingListener <- api.DPIDMapping{
		Action: api.MapActionDelete,
		DPID:   inject.GetDPID(),
		Inject: nil,
	}
}

// close wraps an io.Closer.Close call so that any error can be logged
func close(c io.Closer) {
	if err := c.Close(); err != nil {
		log.
			WithError(err).
			Error("Error when attempting to close resource")
	}
}

// Handle a single connection from a device
func (app *App) handle(conn net.Conn, endpoints connections.Endpoints) error {

	// Close the connection when we are no longer handling it
	defer close(conn)

	var (
		err             error
		buffer          = new(bytes.Buffer)
		match           criteria.Criteria
		header          of.Header
		context         OpenFlowContext
		hCount, piCount int64
		left            uint16
		packetIn        ofp.PacketIn
		featuresReply   ofp.SwitchFeatures
		proxyURL        *url.URL
		proxyTarget     string
	)

	// Parse URL to proxy
	if strings.Index(app.ProxyTo, "://") == -1 {
		proxyTarget = app.ProxyTo
	} else {
		if proxyURL, err = url.Parse(app.ProxyTo); err != nil {
			log.
				WithFields(log.Fields{"proxy": app.ProxyTo}).
				WithError(err).
				Error("Unable to parse URL to SDN controller")
			return err
		}
		if proxyURL.Scheme != "tcp" {
			log.
				WithFields(log.Fields{
					"scheme": proxyURL.Scheme,
					"proxy":  app.ProxyTo,
				}).
				Error("Only TCP connections are supported to SDN controller")
			return err
		}
		proxyTarget = proxyURL.Host
	}

	// Create connection to SDN controller
	proxy := new(connections.TCPConnection)
	if proxy.Connection, err = net.Dial("tcp", proxyTarget); err != nil {
		log.
			WithFields(log.Fields{"proxy": app.ProxyTo}).
			WithError(err).
			Error("Unable to connect to SDN controller")
		return err
	}

	defer close(proxy.Connection)
	proxy.Criteria = criteria.Criteria{}
	inject := injector.NewOFDeviceInjector()
	defer inject.Stop()
	defer app.removeInjector(inject)

	// Anything from the controller, just send to the device
	go func(_conn net.Conn, _proxy *connections.TCPConnection, _inject injector.Injector) {
		// If this fails, bad things are going to happen all over
		// and we just need to drop the connection to device and
		// have everything restart
		if _, err := _inject.Copy(_conn, _proxy.Connection); err != nil {
			log.
				WithError(err).
				WithFields(log.Fields{
					"proxy": _proxy.Connection,
				}).
				Error("Communication from controller to device failed")

			// Force the connection to close, which should
			// cause the read loop below to fail out
			if err = _conn.Close(); err != nil {
				// Ignore
			}
		}
	}(conn, proxy, inject)

	reader := bufio.NewReaderSize(conn, ReadBufferSize)
	for {
		// Read open flow header, if this does not work then we have
		// a serious error, so fail fast and move on
		hCount, err = header.ReadFrom(reader)
		if err != nil && err != io.EOF {
			log.
				WithError(err).
				Debug("Failed to read OpenFlow message header")
			return err
		}

		// If we have a packet in message then this will be tee-ed
		// to those end points that match, else we just proxy to
		// the controller.
		switch header.Type {
		case of.TypePacketIn:
			log.
				WithFields(log.Fields{
					"of_version":     header.Version,
					"of_message":     header.Type.String(),
					"of_transaction": header.Transaction,
					"length":         header.Length,
					"header_length":  hCount,
				}).
				Debug("SENDING: all end-points")

			// Read the packet in message header, have to create a LimitReader as the ofp.packetIn
			// interface does an io.ReadAll, which will read more than the frame size. This reads
			// the packet in header and the packet.
			piCount, err = packetIn.ReadFrom(io.LimitReader(reader, int64(header.Length)-hCount))
			if err != nil || piCount != int64(header.Length)-hCount {
				log.
					WithError(err).
					Debug("Failed to read OpenFlow Packet In message header")
				return err
			}

			// Look for the port in contained in the message
			for _, xm := range packetIn.Match.Fields {
				if xm.Type == ofp.XMTypeInPort {
					context.Port = binary.BigEndian.Uint32(xm.Value)
				}
			}

			// Reset the buffer to read the packet in message and
			// write the headers to the buffer
			buffer.Reset()
			if _, err = context.WriteTo(buffer); err != nil {
				log.
					WithError(err).
					Error("Failed to write OpenFlow context to packet in buffer")
				return err
			}

			if _, err = header.WriteTo(buffer); err != nil {
				log.
					WithError(err).
					Error("Failed to write OpenFlow header to packet in buffer")
				return err
			}

			if _, err = packetIn.WriteTo(buffer); err != nil {
				log.
					WithError(err).
					Error("Failed to write packet in to packet in buffer")
				return err
			}

			// Load and decode the packet being packeted in so we
			// can compare match criteria
			pkt := gopacket.NewPacket(packetIn.Data,
				layers.LayerTypeEthernet,
				gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			eth := pkt.Layer(layers.LayerTypeEthernet)
			if eth == nil {
				log.
					WithFields(log.Fields{
						"packet": fmt.Sprintf("%02x", packetIn.Data),
						"buffer": fmt.Sprintf("%02x", buffer),
					}).
					Debug("Not ethernet packet, can't match")
				continue
			}
			log.
				WithFields(log.Fields{
					"dl_type": fmt.Sprintf("0x%04x", uint16(eth.(*layers.Ethernet).EthernetType)),
				}).
				Debug("match")
			match = criteria.Criteria{
				Set:    criteria.BitDLType,
				DlType: uint16(eth.(*layers.Ethernet).EthernetType),
			}

			// packet in to the SDN controller and packet out
			// to those end points that match the criteria
			if _, err = proxy.Write(buffer.Bytes()[context.Len() : context.Len()+header.Length]); err != nil {
				log.
					WithError(err).
					Error("Unexpected error while writing packet to controller")
				return err
			}
			// TODO loop until all bytes are written

			log.
				WithFields(log.Fields{
					"context":  context.String(),
					"openflow": fmt.Sprintf("%02x", buffer.Bytes()[context.Len():context.Len()+header.Length-packetIn.Length]),
					"packet":   fmt.Sprintf("%02x", packetIn.Data),
				}).
				Debug("packet in")

			if app.TeeRawPackets {
				_, err = endpoints.ConditionalWrite(packetIn.Data, match)
			} else {
				_, err = endpoints.ConditionalWrite(buffer.Bytes()[:context.Len()+header.Length], match)
			}
			if err != nil {
				log.
					WithError(err).
					Error("Unexpected error while writing to TEE clients")
				return err
			}
			// TODO loop until all bytes are written
		case of.TypeFeaturesReply:
			log.WithFields(log.Fields{
				"of_version":     header.Version,
				"of_message":     header.Type.String(),
				"of_transaction": header.Transaction,
				"length":         header.Length,
			}).Debug("Sniffing for DPID")

			piCount, err = featuresReply.ReadFrom(reader)
			app.api.DPIDMappingListener <- api.DPIDMapping{
				Action: api.MapActionAdd,
				DPID:   featuresReply.DatapathID,
				Inject: inject,
			}
			inject.SetDPID(featuresReply.DatapathID)
			context.DatapathID = featuresReply.DatapathID
			log.WithFields(log.Fields{
				"dpid": fmt.Sprintf("0x%016x", featuresReply.DatapathID),
			}).Debug("Sniffed DPID")
			if _, err = header.WriteTo(proxy); err != nil {
				log.
					WithError(err).
					Error("Unexpected error while writing features reply open flow header to controller")
				return err
			}
			if _, err = featuresReply.WriteTo(proxy); err != nil {
				log.
					WithError(err).
					Error("Unexpected error while writing features reply header  to controller")
				return err
			}

			left = header.Length - uint16(hCount) - uint16(piCount)
			if _, err = io.CopyN(proxy, reader, int64(left)); err != nil {
				log.
					WithError(err).
					Error("Unexpected error while writing features reply header  to controller")
				return err
			}

		default:
			// All messages that are not packet in messages are
			// only proxied to the SDN controller. No buffering,
			// just grab bits, push bits.
			log.WithFields(log.Fields{
				"of_version":     header.Version,
				"of_message":     header.Type.String(),
				"of_transaction": header.Transaction,
				"length":         header.Length,
			}).Debug("SENDING: SDN controller")
			if _, err = header.WriteTo(proxy); err != nil && err != io.EOF {
				log.
					WithError(err).
					Error("Unexpected error while writing generic open flow header to controller")
				return err
			}

			left = header.Length - uint16(hCount)
			if _, err = io.CopyN(proxy, reader, int64(left)); err != nil && err != io.EOF {
				log.
					WithError(err).
					Error("Unexpected error while writting open flow message body to controller")
				return err
			}
		}
	}
}

// EstablishEndpointConnections creates connections entities to the configured
// endpoints specified as configuration options
func (app *App) EstablishEndpointConnections() (connections.Endpoints, error) {
	var u *url.URL
	var c connections.Connection
	var tcp *connections.TCPConnection
	var match criteria.Criteria
	var addr string
	var parts, terms []string
	var err error

	endpoints := make([]connections.Connection, len(app.TeeTo))

	for i, spec := range app.TeeTo {
		if len(spec) != 0 {

			// The connection address is of the form
			//    [match],action=url
			// Where [match] is a list of match terms, currently
			// only dl_type is supported.
			parts = strings.Split(spec, ";")
			match = criteria.Criteria{}
			if len(parts) == 1 {
				addr = spec
			} else {
				addr = ""
				for _, part := range parts {
					terms = strings.Split(part, "=")
					switch strings.ToLower(terms[0]) {
					case TermAction:
						addr = terms[1]
					case TermDLType:
						ethType, err := strconv.ParseUint(terms[1], 0, 16)
						match.Set |= criteria.BitDLType
						match.DlType = uint16(ethType)
						if err != nil {
							log.
								WithFields(log.Fields{
									"term":  terms[0],
									"value": terms[1],
								}).
								Error("Unable to convert term to uint16")
							return nil, err
						}
						log.
							WithFields(log.Fields{
								"term":  terms[0],
								"value": terms[1],
							}).
							Debug("Found condition")
					default:
						log.
							WithFields(log.Fields{
								"term":  terms[0],
								"value": terms[1],
							}).
							Error("Unknown end point term")
						return nil, fmt.Errorf("Unknown end point term '%s'", terms[0])
					}
				}
			}

			// Read schema from connection string
			u, err = url.Parse(addr)
			if err != nil {
				log.
					WithFields(log.Fields{"connect": addr}).
					WithError(err).
					Error("Unable to parse connection string")
				return nil, err
			}
			switch strings.ToLower(u.Scheme) {
			default:
				u.Host = addr
				fallthrough
			case SchemeTCP:
				tcp = (&connections.TCPConnection{
					Criteria: match,
				}).Initialize()
				tcp.Connection, err = net.Dial("tcp", u.Host)
				c = tcp
			case SchemeHTTP:
				c = (&connections.HTTPConnection{
					Connection: *u,
					Criteria:   match,
				}).Initialize()
				err = nil
			}
			if err != nil {
				log.
					WithFields(log.Fields{"connection": addr}).
					WithError(err).
					Error("Unable to connect to outbound end point")
				return nil, err
			}
			log.WithFields(log.Fields{
				"connection": addr,
				"c":          c,
				"host":       u.Host,
			}).Info("Created outbound end point connection")

			// Encapsulated call to ListenAndSend to enable error
			// checking
			go func(_c connections.Connection) {
				for {
					if err := _c.ListenAndSend(); err != nil {
						if err == connections.ErrUninitialized {
							log.
								WithError(err).
								Fatal("Attempt to use unitialized connection")
						} else {
							log.
								WithError(err).
								Fatal("Unexpected error")
						}
					}
				}
			}(c)
			endpoints[i] = c
		}
	}
	return endpoints, nil
}

// ListenAndServe Listen for connections from open flow devices and process their
// messages
func (app *App) ListenAndServe() (err error) {
	// Bind to connection for accepting connections
	app.listener, err = net.Listen("tcp", app.ListenOn)
	if err != nil {
		log.
			WithFields(log.Fields{
				"listen-port": app.ListenOn,
			}).
			WithError(err).
			Fatalf("Unable to establish the ability to listen on connection for OpenFlow devices")
	}

	// Loop forever waiting for a connection and processing it
	endpoints := app.endpoints
	for {
		conn, err := app.listener.Accept()
		if err != nil {
			// Not fatal if a connection fails, forget it and move on
			log.
				WithError(err).
				Error("Error while accepting connection")
			continue
		}
		log.WithFields(log.Fields{
			"remote-connection": conn.RemoteAddr().String(),
		}).Debug("Received connection")
		endpoints = app.endpoints
		if !app.ShareConnections {
			endpoints, err = app.EstablishEndpointConnections()
			if err != nil {
				log.
					WithError(err).
					Error("Unable to establish non-shared outbound endpoint connections")
				continue
			}
		}
		go func(_conn net.Conn, _endpoints connections.Endpoints) {
			if err := app.handle(_conn, _endpoints); err != nil {
				log.
					WithError(err).
					WithFields(log.Fields{
						"connection": _conn,
					}).
					Error("Connection to device terminated with an error")
			}
		}(conn, endpoints)
	}
}

func main() {
	var app App

	// This application is not configured by command line options, so
	// if we have an unknown options or they used -h/--help to ask for
	// usage, give it to them
	var flags flag.FlagSet
	err := flags.Parse(os.Args[1:])
	if err != nil {
		if err := envconfig.Usage("", &app); err != nil {
			log.
				WithError(err).
				Error("Unexpected error encountered while displaying usage")
		}
		return
	}

	// Load the application configuration from the environment and initialize
	// the logging system
	err = envconfig.Process("", &app)
	if err != nil {
		log.WithError(err).Fatal("Unable to parse application configuration")
	}

	// Set the logging level, if it can't be parsed then default to warning
	logLevel, err := log.ParseLevel(app.LogLevel)
	if err != nil {
		log.
			WithFields(log.Fields{
				"log-level": app.LogLevel,
			}).
			WithError(err).
			Warn("Unable to parse log level specified, defaulting to Warning")
		logLevel = log.WarnLevel
	}
	log.SetLevel(logLevel)

	// If the help message is requested, then display and return
	if app.ShowHelp {
		if err := envconfig.Usage("", &app); err != nil {
			log.
				WithError(err).
				Error("Unexpected error encountered while displaying usage")
		}
		return
	}

	// Create and invoke the API sub-system
	app.api = api.NewAPI(app.APIOn)
	go app.api.ListenAndServe()

	// Connect to shared outbound end point connections, if requested
	if app.ShareConnections {
		if app.endpoints, err = app.EstablishEndpointConnections(); err != nil {
			log.WithError(err).Fatal("Unable to establish connections to outbound end points, terminating")
		}
	}

	// Listen and serve device requests
	log.Fatal(app.ListenAndServe())
}
