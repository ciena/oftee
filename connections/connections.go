// Package connections provides definitions and protocol specific implementations for end point
// connections. Its primary responsibility is to abstract the specifics of
// end point communication, publish of OpenFlow messages, away from protocol
// specifics, such that the main `oftee` loop can operate against a connection
// independently of protocol specifics.
package connections

import (
	"errors"
	"github.com/ciena/oftee/criteria"
)

// Connection is the interface to an endpoint connection. This interface
// abstracts away the `io.Writer` capability as well as the ability to
// match packet criteria against a packet.
//
// Match compares the connections match criteria against a given criteria,
// presumably derived from an existing packet. Returns `true` if
// the criteria matches, else `false`.
type Connection interface {
	Match(state criteria.Criteria) bool
	GetQueue() chan<- []byte
	ListenAndSend() error
	String() string
}

// ErrUninitialized is the error thrown when the processing loop is invoked
// against connection before a communications channel has been created
var ErrUninitialized = errors.New("connection: attempt to listen on connection before it was initialized")
