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
	// Buffer size when reading
	BUFFER_SIZE = 2048

	// Supported and future supported URL schemes
	SCHEME_TCP   = "tcp"
	SCHEME_HTTP  = "http"
	SCHEME_KAFKA = "kafka"

	// Supported end point configuration terms
	TERM_ACTION  = "action"
	TERM_DL_TYPE = "dl_type"
)

// Maintains the application configuration and runtime state
type App struct {
	ShowHelp         bool     `envconfig:"HELP" default:"false" desc:"show this message"`
	ListenOn         string   `envconfig:"LISTEN_ON" default:":8000" required:"true" desc:"connection on which to listen for an open flow device"`
	ApiOn            string   `envconfig:"API_ON" default:":8002" required:"true" desc:"port on which to listen to accept API requests"`
	ProxyTo          string   `envconfig:"PROXY_TO" default:":8001" required:"true" desc:"connection on which to attach to an SDN controller"`
	TeeTo            []string `envconfig:"TEE_TO" default:":8002" desc:"list of connections on which tee packet in messages"`
	TeeRawPackets    bool     `envconfig:"TEE_RAW" default:"true" desc:"only tee raw packets to the client, openflow headers not included"`
	LogLevel         string   `envconfig:"LOG_LEVEL" default:"debug" desc:"logging level"`
	ShareConnections bool     `envconfig:"SHARE_CONNECTIONS" default:"true" desc:"use shared connections to outbound end points"`

	listener  net.Listener
	endpoints connections.Endpoints
	api       *api.Api
}

type OpenFlowContext struct {
	DatapathID uint64
	Port       uint32
}

func (c *OpenFlowContext) String() string {
	return fmt.Sprintf("[0x%016x, 0x%04x]", c.DatapathID, c.Port)
}

func (c *OpenFlowContext) Len() uint16 {
	return 12
}

func (c *OpenFlowContext) WriteTo(w io.Writer) (int, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf, c.DatapathID)
	binary.BigEndian.PutUint32(buf[8:], c.Port)
	return w.Write(buf)
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

func (app *App) removeInjector(inject *injector.Injector) {
	app.api.DpidMappingListener <- api.DpidMapping{
		Action: api.MAP_ACTION_DELETE,
		Dpid:   inject.Dpid,
		Inject: nil,
	}
}

// Handle a single connection from a device
func (app *App) handle(conn net.Conn, endpoints connections.Endpoints) error {

	// Close the connection when we are no longer handling it
	defer conn.Close()

	var (
		err             error
		buffer          *bytes.Buffer = new(bytes.Buffer)
		match           criteria.Criteria
		header          of.Header
		context         OpenFlowContext
		hCount, piCount int64
		left            uint16
		packetIn        ofp.PacketIn
		featuresReply   ofp.SwitchFeatures
		proxyUrl        *url.URL
		proxyTarget     string
	)

	// Parse URL to proxy
	if strings.Index(app.ProxyTo, "://") == -1 {
		proxyTarget = app.ProxyTo
	} else {
		if proxyUrl, err = url.Parse(app.ProxyTo); err != nil {
			log.
				WithFields(log.Fields{"proxy": app.ProxyTo}).
				WithError(err).
				Error("Unable to parse URL to SDN controller")
			return err
		}
		if proxyUrl.Scheme != "tcp" {
			log.
				WithFields(log.Fields{
					"scheme": proxyUrl.Scheme,
					"proxy":  app.ProxyTo,
				}).
				Error("Only TCP connections are supported to SDN controller")
			return err
		}
		proxyTarget = proxyUrl.Host
	}

	// Create connection to SDN controller
	proxy := new(connections.TcpConnection)
	if proxy.Connection, err = net.Dial("tcp", proxyTarget); err != nil {
		log.
			WithFields(log.Fields{"proxy": app.ProxyTo}).
			WithError(err).
			Error("Unable to connect to SDN controller")
		return err
	}

	defer proxy.Connection.Close()
	proxy.Criteria = criteria.Criteria{}
	inject := injector.NewInjector()
	defer inject.Stop()
	defer app.removeInjector(inject)

	// Anything from the controller, just send to the device
	go inject.Copy(conn, proxy.Connection)

	reader := bufio.NewReaderSize(conn, BUFFER_SIZE)
	for {
		// Read open flow header, if this does not work then we have
		// a serious error, so fail fast and move on
		hCount, err = header.ReadFrom(reader)
		if err != nil {
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
			// TODO need to check errors
			buffer.Reset()
			context.WriteTo(buffer)
			header.WriteTo(buffer)
			packetIn.WriteTo(buffer)

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
				Set:    criteria.BIT_DL_TYPE,
				DlType: uint16(eth.(*layers.Ethernet).EthernetType),
			}

			// packet in to the SDN controller and packet out
			// to those end points that match the criteria
			proxy.Write(buffer.Bytes()[context.Len() : context.Len()+header.Length])
			// TODO loop until all bytes are written
			// TODO if error is returned and connection is broken, reconnect

			log.
				WithFields(log.Fields{
					"context":  context.String(),
					"openflow": fmt.Sprintf("%02x", buffer.Bytes()[context.Len():context.Len()+header.Length-packetIn.Length]),
					"packet":   fmt.Sprintf("%02x", packetIn.Data),
				}).
				Debug("packet in")

			if app.TeeRawPackets {
				endpoints.ConditionalWrite(packetIn.Data, match)
			} else {
				endpoints.ConditionalWrite(buffer.Bytes()[:context.Len()+header.Length], match)
			}
			// TODO loop until all bytes are written
			// TODO if error is returned and connection is broken, reconnect
		case of.TypeFeaturesReply:
			log.WithFields(log.Fields{
				"of_version":     header.Version,
				"of_message":     header.Type.String(),
				"of_transaction": header.Transaction,
				"length":         header.Length,
			}).Debug("Sniffing for DPID")

			piCount, err = featuresReply.ReadFrom(reader)
			app.api.DpidMappingListener <- api.DpidMapping{
				Action: api.MAP_ACTION_ADD,
				Dpid:   featuresReply.DatapathID,
				Inject: inject,
			}
			inject.SetDpid(featuresReply.DatapathID)
			context.DatapathID = featuresReply.DatapathID
			log.WithFields(log.Fields{
				"dpid": fmt.Sprintf("0x%016x", featuresReply.DatapathID),
			}).Debug("Sniffed DPID")
			header.WriteTo(proxy)
			featuresReply.WriteTo(proxy)
			left = header.Length - uint16(hCount) - uint16(piCount)
			io.CopyN(proxy, reader, int64(left))
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
			header.WriteTo(proxy)
			// TODO if error is returned and connection is broken, reconnect

			left = header.Length - uint16(hCount)
			io.CopyN(proxy, reader, int64(left))
		}
	}
}

func (app *App) EstablishEndpointConnections() (connections.Endpoints, error) {
	var u *url.URL
	var c connections.Connection
	var tcp *connections.TcpConnection
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
					case TERM_ACTION:
						addr = terms[1]
					case TERM_DL_TYPE:
						ethType, err := strconv.ParseUint(terms[1], 0, 16)
						match.Set |= criteria.BIT_DL_TYPE
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
			case SCHEME_TCP:
				tcp = &connections.TcpConnection{
					Criteria: match,
				}
				tcp.Connection, err = net.Dial("tcp", u.Host)
				c = tcp
			case SCHEME_HTTP:
				c = &connections.HttpConnection{
					Connection: *u,
					Criteria:   match,
				}
				err = nil
			}
			if err != nil {
				log.
					WithFields(log.Fields{"connection": addr}).
					WithError(err).
					Error("Unable to connect to outbound end point")
				return nil, err
			} else {
				log.WithFields(log.Fields{
					"connection": addr,
					"c":          c,
					"host":       u.Host,
				}).Info("Created outbound end point connection")
				go c.ListenAndSend()
				endpoints[i] = c
			}
		}
	}
	return endpoints, nil
}

// Listen for connections from open flow devices and process their
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
		go app.handle(conn, endpoints)
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
		envconfig.Usage("", &(app))
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
		envconfig.Usage("", &app)
		return
	}

	// Create and invoke the API sub-system
	app.api = api.NewApi(app.ApiOn)
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
