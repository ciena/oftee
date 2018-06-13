package connections

import (
	"io"

	"github.com/ciena/oftee/conditions"
)

type Connection interface {
	io.Writer
	Match(conditions conditions.Conditions) bool
}
