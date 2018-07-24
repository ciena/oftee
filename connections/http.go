package connections

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ciena/oftee/criteria"
	log "github.com/sirupsen/logrus"
)

// HTTP based connection implementation. The connection is represented as a
// net.URL
type HttpConnection struct {
	Connection url.URL
	Criteria   criteria.Criteria
	queue      chan []byte
}

// Initializer to make sure priviate members, that can't function from
// zero state, are set correctly
func (c *HttpConnection) Initialize() *HttpConnection {
	c.queue = make(chan []byte, 25)
	return c
}

// Returns the channel used to queue messages up for delivery
func (c *HttpConnection) GetQueue() chan<- []byte {
	return c.queue
}

// Listens for and processes messages to the target end point over the
// connection
func (c *HttpConnection) ListenAndSend() error {
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
					Debug("sending queued message")
			}
			_, err := c.Write(message)
			if err != nil {
				log.
					WithError(err).
					WithFields(log.Fields{
						"target": c.Connection.String(),
					}).
					Error("failed sending queued message")
			}
		}
	}
}

// Connection in string form
func (c *HttpConnection) String() string {
	if c.queue == nil {
		return fmt.Sprintf("(%s, %d)", c.Connection.String(), -1)
	}
	return fmt.Sprintf("(%s, %d)", c.Connection.String(), len(c.queue))
}

// Writes the specified bytes to the connection by performing a `HTTP POST`
// to the connection `URL`. It is expected that when using this method in
// the context of the OFTee that the entire packet will be represented in a
// single `Write`, although this is not strictly required.
func (c *HttpConnection) Write(b []byte) (n int, err error) {
	_, err = http.Post(c.Connection.String(), "application/octet-stream", bytes.NewReader(b))
	return len(b), err
}

// HTTP connection implementation of the Match method. Simply calls the
// `Match` method on the imbeded `Criteria` data.
func (c *HttpConnection) Match(state criteria.Criteria) bool {
	return c.Criteria.Match(state)
}
