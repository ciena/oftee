package connections

import (
	"bytes"
	"net/http"
	"net/url"

	"github.com/ciena/oftee/criteria"
)

// HTTP based connection implementation. The connection is represented as a
// net.URL
type HttpConnection struct {
	Connection url.URL
	Criteria   criteria.Criteria
}

// Connection in string form
func (c HttpConnection) String() string {
	return c.Connection.String()
}

// Writes the specified bytes to the connection by performing a `HTTP POST`
// to the connection `URL`. It is expected that when using this method in
// the context of the OFTee that the entire packet will be represented in a
// single `Write`, although this is not strictly required.
func (c HttpConnection) Write(b []byte) (n int, err error) {
	_, err = http.Post(c.Connection.String(), "application/octet-stream", bytes.NewReader(b))
	return len(b), err
}

// HTTP connection implementation of the Match method. Simply calls the
// `Match` method on the imbeded `Criteria` data.
func (c HttpConnection) Match(state criteria.Criteria) bool {
	return c.Criteria.Match(state)
}
