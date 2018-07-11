// This package supports sending OF messages from the SDN controller to
// a device. This package is required to allow the sideways injection of
// PacketOut messages into the message stream from the SDN controller.
//
// An Injector instance exists per each device connection and is
// associated with a device DPID in the API package.
package injector

import (
	"fmt"
	"io"

	of "github.com/netrack/openflow"
	log "github.com/sirupsen/logrus"
)

// Used to pass header information from the header reader to the packet processing
// loop
type tlvHeader struct {
	size   int64
	header of.Header
}

// Injector type
type Injector struct {
	Dpid            uint64
	dpid            chan uint64
	controller      chan tlvHeader
	controllerError chan error
	injector        chan []byte
	headerReadWait  chan bool
}

// Creates and Injector instance.
func NewInjector() *Injector {
	return &Injector{
		dpid:            make(chan uint64),
		controller:      make(chan tlvHeader),
		controllerError: make(chan error),
		injector:        make(chan []byte),
		headerReadWait:  make(chan bool),
	}
}

// Reads OpenFlow headers from the src stream and passes them to the the main
// injector message processor, which reads the rest of the message. The header
// reader does a wait after each header is passes to the main loop because
// the two go-routines are operating on the same io.Reader. This is to prevent
// having to maintain a [potentially] large byte buffer and transfer this
// over the channel. You could argue it is not "great" function isolation,
// but for now it works.
func (i *Injector) readHeaders(src io.Reader) {
	var err error
	var tlv tlvHeader
	for {
		tlv.size, err = tlv.header.ReadFrom(src)
		if err != nil {
			i.controllerError <- err
			break
		}
		i.controller <- tlv

		// Pause reading from controller, until rest of packet message
		// is copied from the controller to the device
		<-i.headerReadWait
	}
}

// Public packet injection method (packet out)
func (i *Injector) Inject(message []byte) {
	i.injector <- message
}

func (i *Injector) SetDpid(dpid uint64) {
	i.dpid <- dpid
}

// Copies OpenFlow messages from the source (`src`) to the destination (`dest`).
// The copy my respect the boundaries of the OpenFlow messages so that PacketOut
// messages can be inject into the stream without corrupting it.
func (i *Injector) Copy(dst io.Writer, src io.Reader) (int64, error) {
	var err error
	var tlv tlvHeader
	var message []byte

	// Start the header reader
	go i.readHeaders(src)

	// Loop waiting for a packet to send on, either from the controller or
	// injected as a packet out
	for {
		select {
		case i.Dpid = <-i.dpid:
		case tlv = <-i.controller:
			tlv.header.WriteTo(dst)
			_, err = io.CopyN(dst, src, int64(tlv.header.Length)-tlv.size)
			if err != nil {
				log.
					WithError(err).
					Fatal("Error while attempting to write packet to device")

			}
			i.headerReadWait <- true
			// TODO handle case where not all the bytes were copied

		case err = <-i.controllerError:
			log.
				WithError(err).
				Debug("Failed to read OpenFlow message header")
			return 0, err
		case message = <-i.injector:
			// TODO Validate the the frame is legal, at least
			// that the length of the Frame is the same as the
			// size of the message array
			log.WithFields(log.Fields{
				"dpid":    fmt.Sprintf("0x%016x", i.Dpid),
				"message": fmt.Sprintf("%02x", message),
			}).Debug("Writing packet out to device")
			_, err = dst.Write(message)
			if err != nil {
				log.
					WithFields(log.Fields{
						"dpid": fmt.Sprintf("0x%016x", i.Dpid),
					}).
					WithError(err).
					Fatal("Error while attempting to write packet to device")

			}
		}
	}
}
