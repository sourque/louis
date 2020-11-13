package techs

import (
	"fmt"

	"github.com/sourque/louis/correlate"
	"github.com/sourque/louis/events"
)

type L1003 struct {
	techBase
}

func (t L1003) Name() string {
	return "eBPF Module Persistence"
}

func (t L1003) Scan(e events.Event) Finding {
	res := Finding{}
	permittedBins := []string{
		"/usr/bin/su",
		"/usr/bin/sudo",
	}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		if events.CStr(ev.Filename[:]) == "/etc/shadow" {
			callingBin, err := correlate.Bin(events.GetAll(), e.FetchPid())
			if err != nil {
				fmt.Println("l1002: error in fetching correlate bin:", err)
				return res
			}
			if !correlate.InList(permittedBins, callingBin) {
				res.Found = true
				res.Level = LevelWarn
			}
		}
	}
	return res
}
