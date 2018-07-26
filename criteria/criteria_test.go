package criteria

import (
	"testing"
)

func TestZeroMatch(t *testing.T) {
	c1 := Criteria{}
	c2 := Criteria{}

	if !c1.Match(c2) || !c2.Match(c1) {
		t.Fail()
	}
}

func TestIdentifyMatch(t *testing.T) {
	c1 := Criteria{
		Set:    BitDLType,
		DlType: 0x0800,
	}

	if !c1.Match(c1) {
		t.Fail()
	}
}

func TestLessThanMatch(t *testing.T) {
	c1 := Criteria{}
	c2 := Criteria{
		Set:    BitDLType,
		DlType: 0x0800,
	}

	if !c1.Match(c2) {
		t.Fail()
	}
}

func TestGreaterThanMatch(t *testing.T) {
	c1 := Criteria{
		Set:    BitDLType,
		DlType: 0x0800,
	}
	c2 := Criteria{}
	if c1.Match(c2) {
		t.Fail()
	}
}

func TestDiffDlTypeMatch(t *testing.T) {
	c1 := Criteria{
		Set:    BitDLType,
		DlType: 0x0800,
	}
	c2 := Criteria{
		Set:    BitDLType,
		DlType: 0x0810,
	}

	if c1.Match(c2) {
		t.Fail()
	}
}
