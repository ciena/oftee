package connections

import (
	"github.com/ciena/oftee/conditions"
	of "github.com/netrack/openflow"
)

type Outbound []Connection

// Iterates over all outbound connections and if the condition matches
// writes to the buffer
func (o Outbound) Write(b []byte) (n int, err error) {
	for _, conn := range o {
		n, err = conn.Write(b)
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (o Outbound) ConditionalWrite(b []byte, state conditions.Conditions) (n int, err error) {
	for _, conn := range o {
		if conn.Match(state) {
			n, err = conn.Write(b)
			if err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (o Outbound) ConditionalWriteTo(h of.Header, state conditions.Conditions) (n int64, err error) {
	for _, conn := range o {
		if conn.Match(state) {
			n, err = h.WriteTo(conn)
			if err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}
