package types

import (
	"errors"
	"fmt"
	"strings"
)

func ParseUProbeLink(s string) (UProbeLink, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) < 2 {
		return UProbeLink{}, errors.New("a uprobe link needs to consist of executable:symbol")
	}
	return UProbeLink{
		Executable: parts[0],
		Symbol:     parts[1],
	}, nil
}

type UProbeLink struct {
	Executable string
	Symbol     string
}

func (u *UProbeLink) String() string {
	return fmt.Sprintf("%s:%s", u.Executable, u.Symbol)
}
