package connections

import (
	"github.com/ciena/oftee/criteria"
)

// Endpoints represents a list (array) of connections
type Endpoints []Connection

// Iterates over all endpoint connections and write the given bytes to the
// connection. If a write to an any single connection fails then processing
// of the remaining writes is not attempted and an error is returned.
func (eps Endpoints) Write(b []byte) (n int, err error) {
	for _, conn := range eps {
		n, err = conn.Write(b)
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Iterates over all endpoint connections and if the connection's criteria
// matches the given state critera then write the given bytes to the connection.
// If a write to an any single connection fails then processing of the
// remaining writes is not attempted and an error is returned.
func (eps Endpoints) ConditionalWrite(b []byte, state criteria.Criteria) (n int, err error) {
	for _, conn := range eps {
		if conn.Match(state) {
			n, err = conn.Write(b)
			if err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}
