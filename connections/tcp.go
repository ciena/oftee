package connections

import (
	"errors"
	"net"

	"github.com/ciena/oftee/conditions"
)

type TcpConnection struct {
	Connection net.Conn
	Conditions conditions.Conditions
}

func (c TcpConnection) Write(b []byte) (n int, err error) {
	if c.Connection != nil {
		return c.Connection.Write(b)
	}
	return 0, errors.New("No connection established")
}

func (c TcpConnection) Match(conditions conditions.Conditions) bool {
	return false
}
