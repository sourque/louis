package techs

import (
	"fmt"

	"github.com/sourque/louis/correlate"
	"github.com/sourque/louis/events"
)

// L1002 is non-trusted users or programs reading /etc/shadow.
type L1002 struct{}

func (t L1002) Name() string {
	return "Suspcious /etc/shadow Access"
}

func (t L1002) Scan(e events.Event) Finding {
	res := Finding{}
	permittedBins := []string{
		"/usr/bin/su",
		"/usr/bin/sudo",
	}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		if events.ReadCString(ev.Filename[:]) == "/etc/shadow" {
			callingBin, err := correlate.Bin(events.GetAll(), e.FetchPid())
			if err != nil {
				fmt.Println("l1002: error in fetching correlate bin:", err)
				return res
			}
			if !correlate.InList(permittedBins, callingBin) {
				res.Found = true
				res.Level = levelWarn
			}
		}
	}
	return res
}

func (t L1002) Check() (bool, int) {
	return true, levelNil
}

func (t L1002) Clean() {
}

func (t L1002) Mitigate() {
}
