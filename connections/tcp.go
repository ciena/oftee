package connections

import (
	"errors"
	"net"

	"github.com/ciena/oftee/criteria"
)

// TCP based connection implementation. The connection is represented as a
// net.Conn
type TcpConnection struct {
	Connection net.Conn
	Criteria   criteria.Criteria
}

// Connection in string form
func (c TcpConnection) String() string {
	return c.Connection.RemoteAddr().String()
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
func (c TcpConnection) Write(b []byte) (n int, err error) {
	if c.Connection != nil {
		return c.Connection.Write(b)
	}
	return 0, errors.New("No connection established")
}

// TCP connection implementation of the Match method. Simply calls the
// `Match` method on the imbeded `Criteria` data.
func (c TcpConnection) Match(state criteria.Criteria) bool {
	return c.Criteria.Match(state)
}
