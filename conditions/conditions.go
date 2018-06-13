package conditions

type Conditions struct {
	Set    uint64
	DlType uint16
}

const (
	BIT_EMPTY   = 0x0
	BIT_DL_TYPE = 1 << 0
)

func (c Conditions) Match(state Conditions) bool {

	if c.Set&BIT_DL_TYPE > 0 && (state.Set&BIT_DL_TYPE == 0 || c.DlType != state.DlType) {
		return false
	}
	return true
}
