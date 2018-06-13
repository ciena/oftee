package connections

import (
	"bytes"
	"net/http"
	"net/url"

	"github.com/ciena/oftee/conditions"
	log "github.com/sirupsen/logrus"
)

type HttpConnection struct {
	Connection url.URL
	Conditions conditions.Conditions
}

func (c HttpConnection) Write(b []byte) (n int, err error) {
	_, err = http.Post(c.Connection.String(), "application/data", bytes.NewReader(b))
	return len(b), err
}

func (c HttpConnection) Match(state conditions.Conditions) bool {

	b := c.Conditions.Match(state)
	log.WithFields(log.Fields{
		"match": state,
		"want":  c.Conditions,
		"equal": b,
	}).Debug("MATCH")
	return b
}
