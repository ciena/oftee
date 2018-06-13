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

	"github.com/ciena/oftee/conditions"
	"github.com/ciena/oftee/connections"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kelseyhightower/envconfig"
	of "github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
)

const (
	BUFFER_SIZE = 2048

	SCHEME_TCP   = "tcp"
	SCHEME_HTTP  = "http"
	SCHEMA_KAFKA = "kafka"

	TERM_ACTION  = "action"
	TERM_DL_TYPE = "dl_type"
)

// Maintains the application configuration and runtime state
type App struct {
	ShowHelp bool     `envconfig:"HELP" default:"false" desc:"show this message"`
	ListenOn string   `envconfig:"LISTEN_ON" default:":8000" required:"true" desc:"connection on which to listen for an open flow device"`
	ProxyTo  string   `envconfig:"PROXY_TO" default:":8001" required:"true" desc:"connection on which to attach to an SDN controler"`
	TeeTo    []string `envconfig:"TEE_TO" default:":8002" desc:"list of connections on which tee packet in messages"`
	LogLevel string   `envconfig:"LOG_LEVEL" default:"debug" desc:"logging level"`

	listener net.Listener
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (app *App) handle(conn net.Conn) {
	var err error
	var u *url.URL
	var c connections.Connection
	var hc *connections.HttpConnection
	var tcp *connections.TcpConnection
	var buffer *bytes.Buffer = nil
	var proxied, buffered connections.Outbound
	var list *connections.Outbound
	var match conditions.Conditions
	var addr string
	var parts, terms []string
	for _, spec := range append([]string{app.ProxyTo}, app.TeeTo...) {
		log.Debugf("SPEC: %s", spec)
		if len(spec) != 0 {

			// The connection address is of the form
			//    [match],action=url
			// Where [match] is a list of match terms, currently
			// only dl_type is supported.
			parts = strings.Split(spec, ";")
			log.Debugf("PARTS: %+v", parts)
			match = conditions.Conditions{}
			if len(parts) == 1 {
				addr = spec
			} else {
				addr = ""
				for _, part := range parts {
					terms = strings.Split(part, "=")
					log.Debugf("%s --> %s and %d", part, terms[0], terms[1])
					switch strings.ToLower(terms[0]) {
					case TERM_ACTION:
						addr = terms[1]
					case TERM_DL_TYPE:
						ethType, err := strconv.ParseUint(terms[1], 0, 16)
						match.Set |= conditions.BIT_DL_TYPE
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
				tcp.Conditions = match
				c = *tcp
				list = &proxied
			case SCHEME_HTTP:
				hc = new(connections.HttpConnection)
				hc.Connection = *u
				hc.Conditions = match
				c = *hc
				err = nil
				buffer = new(bytes.Buffer)
				list = &buffered
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
				}).Infof("Created outbound connection")
				*list = append(*list, c)
			}
		}
	}

	// Anything from the controller, just send to the device
	go io.Copy(conn, proxied[0].(connections.TcpConnection).Connection)

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

			header.WriteTo(proxied)
			packetIn.WriteTo(proxied)
			if buffer != nil {
				buffer.Reset()
				header.WriteTo(buffer)
				packetIn.WriteTo(buffer)
			}
			left = header.Length - uint16(hCount) - uint16(piCount)
			for left > 0 {
				count, err = reader.Read(buf[:min(int(left), BUFFER_SIZE)])
				if err != nil {
					log.Debugf("ERROR %s", err)
					break
				}
				proxied.Write(buf[:count])
				if buffer != nil {
					buffer.Write(buf[:count])
				}
				left -= uint16(count)
			}
			// Send message to those outbound connections that
			// require buffering
			if buffer != nil {
				pkt := gopacket.NewPacket(buffer.Bytes()[hCount+piCount:], layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
				eth := pkt.Layer(layers.LayerTypeEthernet)
				match = conditions.Conditions{
					Set:    conditions.BIT_DL_TYPE,
					DlType: uint16(eth.(*layers.Ethernet).EthernetType),
				}
				buffered.ConditionalWrite(buffer.Bytes(), match)
			}
		} else {
			log.WithFields(log.Fields{
				"of_version":     header.Version,
				"of_message":     header.Type.String(),
				"of_transaction": header.Transaction,
				"length":         header.Length,
			}).Debug("SENDING: SDN controller")
			header.WriteTo(proxied[0])
			left = header.Length - uint16(hCount)
			for left > 0 {
				count, err = reader.Read(buf[:min(int(left), BUFFER_SIZE)])
				if err != nil {
					log.Debugf("ERROR %s", err)
					break
				}
				proxied[0].Write(buf[:count])

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
		return err
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
	err = envconfig.Process("myapp", &app)
	if err != nil {
		log.Fatalf("Unable to parse configuration : %s\n", err)
	}

	logLevel, err := log.ParseLevel(app.LogLevel)
	if err != nil {
		log.Warnf("Unable to parse log level specififed '%s', defaulting to 'warning' : %s", app.LogLevel, err)
		logLevel = log.WarnLevel
	}
	log.SetLevel(logLevel)

	// If the help message is requested, then display and return
	if app.ShowHelp {
		envconfig.Usage("", &(app))
		return
	}

	// Listen and serve requests
	log.Fatal(app.ListenAndServe())
}
