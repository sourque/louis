package techs

import (
	"os"
	"strings"

	"github.com/sourque/louis/events"
)

type L1004 struct {
	techBase
}

func (t L1004) Name() string {
	return "File Modified in /etc/"
}

func (t L1004) Scan(e events.Event) Finding {
	res := Finding{}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		if int(ev.Flags) != os.O_RDONLY {
			if strings.Contains(events.CStr(ev.Filename[:]), "/etc/") || strings.Contains(events.CStr(ev.Pwd[:]), "etc") {
				res.Found = true
				res.Level = LevelErr
			}
		}
	}
	return res
}
