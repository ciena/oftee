package connections

import (
	"errors"
	"fmt"
	"net"

	"github.com/ciena/oftee/criteria"
	log "github.com/sirupsen/logrus"
)

// TCPConnection is the TCP based connection implementation. The connection is
// represented as a net.Conn
type TCPConnection struct {
	Connection net.Conn
	Criteria   criteria.Criteria
	queue      chan []byte
}

// Initialize makes sure priviate members, that can't function from
// zero state, are set correctly
func (c *TCPConnection) Initialize() *TCPConnection {
	c.queue = make(chan []byte, 25)
	return c
}

// GetQueue returns the channel used to queue messages up for delivery
func (c *TCPConnection) GetQueue() chan<- []byte {
	return c.queue
}

// ListenAndSend listens for and processes messages to the target end point
// over the connection
func (c *TCPConnection) ListenAndSend() error {

	// If queue not created, error out
	if c.queue == nil {
		log.
			WithError(ErrUninitialized).
			Error("MUST initialize connection before use")
		return ErrUninitialized

	}
	for {
		select {
		case message := <-c.queue:
			if log.GetLevel() >= log.DebugLevel {
				log.
					WithFields(log.Fields{
						"data": fmt.Sprintf("%02x", message),
					}).
					Debug("send queued message")
			}
			_, err := c.Write(message)
			if err != nil {
				log.
					WithError(err).
					WithFields(log.Fields{
						"target": c.Connection,
					}).
					Error("failed sending queued message")
			}
		}
	}
}

// Connection in string form
func (c *TCPConnection) String() string {
	if c.queue == nil {
		return fmt.Sprintf("(%s, %d)", c.Connection.RemoteAddr().String(), -1)
	}
	return fmt.Sprintf("(%s, %d)", c.Connection.RemoteAddr().String(), len(c.queue))
}

// Writes the specified bytes to the connection by performing a
// `net.Conn.Write` to the connection.
//
// It is expected that when using this method for a `tee` end point that the
// entire packet will be represented in a single `Write`, although this is not
// strictly required.
//
// When using this method to communicate to the SDN controller, it is not
// expected to include the entire packet in a single `Write`.
func (c *TCPConnection) Write(b []byte) (n int, err error) {
	if c.Connection != nil {
		return c.Connection.Write(b)
	}
	return 0, errors.New("No connection established")
}

// Match is the TCP connection implementation of the Match method. Simply
// calls the `Match` method on the imbeded `Criteria` data.
func (c *TCPConnection) Match(state criteria.Criteria) bool {
	return c.Criteria.Match(state)
}
