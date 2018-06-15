package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/kelseyhightower/envconfig"
	of "github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
)

type App struct {
	ShowHelp   bool   `envconfig:"HELP" default:"false" desc:"show this message"`
	OfTeeApi   string `envconfig:"OFTEE_API" default:"http://127.0.0.1:8002" desc:"HOST:PORT on which to connect to OFTEE REST API"`
	Device     string `envconfig:"DEVICE" required:"true" desc:"DPID of device on which to packet out"`
	Port       string `envconfig:"PORT" required:"true" desc:"Port on device on which to packet out"`
	PacketFile string `envconfig:"PACKET_FILE" required:"true" desc:"File from which to read packet to send, or '-' for stdin"`
}

func main() {
	var app App

	var flags flag.FlagSet
	err := flags.Parse(os.Args[1:])
	if err != nil {
		envconfig.Usage("", &(app))
		return
	}

	err = envconfig.Process("", &app)
	if err != nil {
		log.
			WithError(err).
			Fatal("Unable to process configuration")
	}
	if app.ShowHelp {
		envconfig.Usage("", &app)
		return
	}

	// Read packet file, which is expected to be a space separate bunch of
	// bytes
	var data bytes.Buffer
	var scanner *bufio.Scanner
	if app.PacketFile == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		reader, err := os.OpenFile(app.PacketFile, os.O_RDONLY, 0)
		if err == nil {
			scanner = bufio.NewScanner(reader)
		}
	}
	if err != nil {
		log.
			WithFields(log.Fields{
				"file": app.PacketFile,
			}).
			WithError(err).
			Fatal("Unable to read packet file")
	}

	scanner.Split(bufio.ScanWords)
	var val uint64
	for scanner.Scan() {
		val, err = strconv.ParseUint(scanner.Text(), 16, 8)
		if err != nil {
			log.
				WithFields(log.Fields{
					"byte": scanner.Text(),
				}).
				WithError(err).
				Fatal("Unable to parse value to byte")
		}
		data.WriteByte(uint8(val))
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading input:", err)
	}

	// Process port constants
	var portNo ofp.PortNo
	switch strings.ToUpper(app.Port) {
	case "IN":
		portNo = 0xfffffff8
	case "TABLE":
		portNo = 0xfffffff9
	case "NORMAL":
		portNo = 0xfffffffa
	case "FLOOD":
		portNo = 0xfffffffb
	case "ALL":
		portNo = 0xfffffffc
	case "CONTROLLER":
		portNo = 0xfffffffd
	case "LOCAL":
		portNo = 0xfffffffe
	default:
		val, err := strconv.ParseUint(app.Port, 10, 32)
		if err != nil {
			log.
				WithFields(log.Fields{
					"port": app.Port,
				}).
				WithError(err).
				Fatal("Unable to parse specified port value")
		}
		portNo = ofp.PortNo(val)
	}

	// Build packet out message
	packet := &bytes.Buffer{}
	pktOut := ofp.PacketOut{
		Buffer:  ofp.NoBuffer,
		InPort:  ofp.PortAny,
		Actions: ofp.Actions{&ofp.ActionOutput{portNo, ofp.ContentLenNoBuffer}},
	}
	req := of.NewRequest(of.TypePacketOut, packet)

	pktOut.WriteTo(packet)
	packet.Write(data.Bytes())

	message := &bytes.Buffer{}
	req.WriteTo(message)

	log.Debug("POSTING")
	url := fmt.Sprintf("%s/oftee/%s", app.OfTeeApi, app.Device)
	resp, err := http.Post(url, "application/octet-stream", message)
	if err != nil {
		log.
			WithFields(log.Fields{
				"oftee": app.OfTeeApi,
			}).
			WithError(err).
			Fatal("Unable to connect to oftee API end point")
	} else if int(resp.StatusCode/100) != 2 {
		log.
			WithFields(log.Fields{
				"oftee":         app.OfTeeApi,
				"response-code": resp.StatusCode,
				"response":      resp.Status,
			}).
			Fatal("Non success code returned from oftee")
	}
}
