// OFTEE command to start a OpenFlow tee proxy. This command parses the
// environment for configuration information and then starts a processing
// loop for OpenFlow messages.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ciena/oftee/connections"
	"github.com/ciena/oftee/criteria"
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
	ShowHelp bool     `envconfig:"HELP" default:"false" desc:"show this message"`
	ListenOn string   `envconfig:"LISTEN_ON" default:":8000" required:"true" desc:"connection on which to listen for an open flow device"`
	ProxyTo  string   `envconfig:"PROXY_TO" default:":8001" required:"true" desc:"connection on which to attach to an SDN controller"`
	TeeTo    []string `envconfig:"TEE_TO" default:":8002" desc:"list of connections on which tee packet in messages"`
	LogLevel string   `envconfig:"LOG_LEVEL" default:"debug" desc:"logging level"`

	listener net.Listener
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

// Handle a single connection to a device
func (app *App) handle(conn net.Conn) {
	var err error
	var u *url.URL
	var c connections.Connection
	var hc *connections.HttpConnection
	var tcp *connections.TcpConnection
	var buffer *bytes.Buffer = new(bytes.Buffer)
	var endpoints connections.Endpoints = make([]connections.Connection,
		len(app.TeeTo)+1) // Tees + proxy
	var match criteria.Criteria
	var addr string
	var parts, terms []string
	for i, spec := range append([]string{app.ProxyTo}, app.TeeTo...) {
		log.Debugf("SPEC: %s", spec)
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
							log.WithFields(log.Fields{
								"term":  terms[0],
								"value": terms[1],
							}).Fatal("Unable to convert term to uint16")
						}
						log.WithFields(log.Fields{
							"term":  terms[0],
							"value": terms[1],
						}).Debug("Found condition")
					default:
						log.WithFields(log.Fields{
							"term":  terms[0],
							"value": terms[1],
						}).Fatal("Unknown end point term")
					}
				}
			}

			// Read schema from connection string
			u, err = url.Parse(addr)
			if err != nil {
				log.WithFields(log.Fields{
					"connect": addr,
					"error":   err,
				}).Fatal("Unable to parse connection string")
			}
			switch strings.ToLower(u.Scheme) {
			default:
				u.Host = addr
				fallthrough
			case SCHEME_TCP:
				tcp = new(connections.TcpConnection)
				tcp.Connection, err = net.Dial("tcp", u.Host)
				tcp.Criteria = match
				c = *tcp
			case SCHEME_HTTP:
				hc = new(connections.HttpConnection)
				hc.Connection = *u
				hc.Criteria = match
				c = *hc
				err = nil
			}
			if err != nil {
				log.WithFields(log.Fields{
					"connection": addr,
					"error":      err,
				}).Fatal("Unable to connect to outbound end point")
			} else {
				log.WithFields(log.Fields{
					"connection": addr,
					"c":          c,
					"tcp":        tcp,
					"hc":         hc,
					"host":       u.Host,
				}).Infof("Created outbound end point connection")
				endpoints[i] = c
			}
		}
	}

	// Anything from the controller, just send to the device
	go io.Copy(conn, endpoints[0].(connections.TcpConnection).Connection)

	reader := bufio.NewReaderSize(conn, BUFFER_SIZE)
	buf := make([]byte, BUFFER_SIZE)
	var header of.Header
	var hCount, piCount int64
	var left uint16
	var count int
	var packetIn ofp.PacketIn
	for {
		// Read open flow header, if this does not work then we have
		// a serious error, so fail fast and move on
		hCount, err = header.ReadFrom(reader)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err.Error(),
			}).Debug("Failed to read OpenFlow message header")
			break
		}

		// If we have a packet in message then this will be tee-ed
		// to those end points that match, else we just proxy to
		// the controller.
		if header.Type == of.TypePacketIn {
			log.WithFields(log.Fields{
				"of_version":     header.Version,
				"of_message":     header.Type.String(),
				"of_transaction": header.Transaction,
				"length":         header.Length,
			}).Debug("SENDING: all end-points")
			piCount, err = packetIn.ReadFrom(reader)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err.Error(),
				}).Debug("Failed to read OpenFlow Packet In message header")
				break
			}

			// Reset the buffer to read the packet in message and
			// write the headers to the buffer
			buffer.Reset()
			header.WriteTo(buffer)
			packetIn.WriteTo(buffer)

			// Read and buffer the rest of the packet
			left = header.Length - uint16(hCount) - uint16(piCount)
			for left > 0 {
				count, err = reader.Read(buf[:min(int(left), BUFFER_SIZE)])
				if err != nil {
					log.Debugf("ERROR %s", err)
					break
				}
				buffer.Write(buf[:count])
				left -= uint16(count)
			}

			// Load and decode the packet being packeted in so we
			// can compare match criteria
			pkt := gopacket.NewPacket(buffer.Bytes()[hCount+piCount:],
				layers.LayerTypeEthernet,
				gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			eth := pkt.Layer(layers.LayerTypeEthernet)
			match = criteria.Criteria{
				Set:    criteria.BIT_DL_TYPE,
				DlType: uint16(eth.(*layers.Ethernet).EthernetType),
			}
			endpoints.ConditionalWrite(buffer.Bytes(), match)
		} else {
			log.WithFields(log.Fields{
				"of_version":     header.Version,
				"of_message":     header.Type.String(),
				"of_transaction": header.Transaction,
				"length":         header.Length,
			}).Debug("SENDING: SDN controller")
			header.WriteTo(endpoints[0])
			left = header.Length - uint16(hCount)
			for left > 0 {
				count, err = reader.Read(buf[:min(int(left), BUFFER_SIZE)])
				if err != nil {
					log.Debugf("ERROR %s", err)
					break
				}
				endpoints[0].Write(buf[:count])

				left -= uint16(count)
			}
		}
	}
}

// Listen for connections from open flow devices and process their
// messages
func (app *App) ListenAndServe() (err error) {

	// Bind to connection for accepting connections
	app.listener, err = net.Listen("tcp", app.ListenOn)
	if err != nil {
		log.Fatalf("Unable to establish the ability to listen on connection '%s' : %s", app.ListenOn, err)
	}

	// Loop forever waiting for a connection and processing it
	for {
		conn, err := app.listener.Accept()
		if err != nil {
			// Not fatal if a connection fails, forget it and move on
			log.Errorf("Error while accepting connection : %s", err)
		}
		log.Debugf("Received connection: %s", conn.RemoteAddr().String())
		go app.handle(conn)
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
		log.Fatalf("Unable to parse configuration : %s\n", err)
	}

	// Set the logging level, if it can't be parsed then default to warning
	logLevel, err := log.ParseLevel(app.LogLevel)
	if err != nil {
		log.Warnf("Unable to parse log level specififed '%s', defaulting to 'warning' : %s", app.LogLevel, err)
		logLevel = log.WarnLevel
	}
	log.SetLevel(logLevel)

	// If the help message is requested, then display and return
	if app.ShowHelp {
		envconfig.Usage("", &app)
		return
	}

	// Listen and serve requests
	log.Fatal(app.ListenAndServe())
}
