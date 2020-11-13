package techs

import (
	"os"
	"strings"

	"github.com/sourque/louis/correlate"
	"github.com/sourque/louis/events"
)

type T1547 struct {
	techBase
}

func (t T1547) Name() string {
	return "Kernel Modules Persistence"
}

func (t T1547) Scan(e events.Event) Finding {
	res := Finding{}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		fileName := events.CStr(ev.Filename[:])
		if strings.Contains(fileName, "authorized_keys") {
			if int(ev.Flags) != os.O_RDONLY {
				if ev.RetVal < 0 {
					res.Found = true
					res.Level = LevelWarn
					return res
				}
				owner, err := correlate.Owner(fileName)
				if err != nil {
					res.Found = true
					res.Level = LevelCrit
					return res
				}
				if owner != ev.Uid {
					res.Found = true
					res.Level = LevelCrit
					return res
				}
			}
		}
	}
	return res
}
