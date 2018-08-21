// Package injector supports sending OF messages from the SDN controller to
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
type Injector interface {
	SetDPID(uint64)
	GetDPID() uint64
	Inject([]byte)
	Stop()
	Copy(io.Writer, io.Reader) (int64, error)
}

// OFDeviceInjector implementation of Injector for OpenFlow devices
type OFDeviceInjector struct {
	DPID            uint64
	dpid            chan uint64
	controller      chan tlvHeader
	controllerError chan error
	injector        chan []byte
	headerReadWait  chan bool
	headerStop      chan bool
	mainStop        chan bool
}

// NewOFDeviceInjector creates an Injector instance.
func NewOFDeviceInjector() Injector {
	return &OFDeviceInjector{
		dpid:            make(chan uint64, 10),
		controller:      make(chan tlvHeader),
		controllerError: make(chan error),
		injector:        make(chan []byte, 100),
		headerReadWait:  make(chan bool),
		headerStop:      make(chan bool),
		mainStop:        make(chan bool),
	}
}

// Reads OpenFlow headers from the src stream and passes them to the the main
// injector message processor, which reads the rest of the message. The header
// reader does a wait after each header is passes to the main loop because
// the two go-routines are operating on the same io.Reader. This is to prevent
// having to maintain a [potentially] large byte buffer and transfer this
// over the channel. You could argue it is not "great" function isolation,
// but for now it works.
func (i *OFDeviceInjector) readHeaders(src io.Reader) {
	var err error
	var tlv tlvHeader
	for {
		select {
		case <-i.headerStop:
			return
		default:
			tlv.size, err = tlv.header.ReadFrom(src)
			if err != nil && err != io.EOF {
				i.controllerError <- err
				return
			}
			i.controller <- tlv

			// Pause reading from controller, until rest of packet message
			// is copied from the controller to the device
			select {
			case <-i.headerStop:
				return
			case <-i.headerReadWait:
			}
		}
	}
}

// Inject injects a packet to the managed device (packet out)
func (i *OFDeviceInjector) Inject(message []byte) {
	i.injector <- message
}

// SetDPID associates a DPID with an injector
func (i *OFDeviceInjector) SetDPID(dpid uint64) {
	i.dpid <- dpid
}

// GetDPID returns the associated DPID
func (i *OFDeviceInjector) GetDPID() uint64 {
	return i.DPID
}

// Stop sends stop messages to the go routines
func (i *OFDeviceInjector) Stop() {
	i.headerStop <- true
	i.mainStop <- true
}

// Copy copies OpenFlow messages from the source (`src`) to the destination (`dest`).
// The copy my respect the boundaries of the OpenFlow messages so that PacketOut
// messages can be inject into the stream without corrupting it.
func (i *OFDeviceInjector) Copy(dst io.Writer, src io.Reader) (int64, error) {
	var err error
	var tlv tlvHeader
	var message []byte

	// Start the header reader
	go i.readHeaders(src)

	// Loop waiting for a packet to send on, either from the controller or
	// injected as a packet out
	for {
		select {
		case <-i.mainStop:
			return 0, nil
		case i.DPID = <-i.dpid:
		case tlv = <-i.controller:
			_, err = tlv.header.WriteTo(dst)
			if err != nil && err != io.EOF {
				log.
					WithError(err).
					Error("Error while attempting to write header to device")
				return 0, err
			}
			_, err = io.CopyN(dst, src, int64(tlv.header.Length)-tlv.size)
			if err != nil && err != io.EOF {
				log.
					WithError(err).
					Error("Error while attempting to write packet to device")
				return 0, err

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
				"dpid":    fmt.Sprintf("0x%016x", i.DPID),
				"message": fmt.Sprintf("%02x", message),
			}).Debug("Writing packet out to device")
			_, err = dst.Write(message)
			if err != nil && err != io.EOF {
				log.
					WithFields(log.Fields{
						"dpid": fmt.Sprintf("0x%016x", i.DPID),
					}).
					WithError(err).
					Error("Error while attempting to write packet to device")
				return 0, err

			}
		}
	}
}
