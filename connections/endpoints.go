package connections

import (
	"github.com/ciena/oftee/criteria"
	log "github.com/sirupsen/logrus"
)

// Endpoints represents a list (array) of connections
type Endpoints []Connection

// Iterates over all endpoint connections and write the given bytes to the
// connection. If a write to an any single connection fails then processing
// of the remaining writes is not attempted and an error is returned.
func (eps Endpoints) Write(b []byte) (n int, err error) {
	for _, conn := range eps {
		conn.GetQueue() <- b
	}
	return n, nil
}

// Iterates over all endpoint connections and if the connection's criteria
// matches the given state critera then write the given bytes to the connection.
// If a write to an any single connection fails then processing of the
// remaining writes is not attempted and an error is returned.
func (eps Endpoints) ConditionalWrite(b []byte, state criteria.Criteria) (n int, err error) {
	for _, conn := range eps {
		if log.GetLevel() == log.DebugLevel {
			log.
				WithFields(log.Fields{
					"connection": conn.String(),
					"match":      conn.Match(state),
				}).
				Debug("Checking")
		}
		if conn.Match(state) {
			conn.GetQueue() <- b
		}
	}
	return n, nil
}
