package techs

import (
	"os"
	"strings"

	"github.com/sourque/louis/events"
)

type L1005 struct {
	techBase
}

func (t L1005) Name() string {
	return "File Modification in Temporary Filesystem"
}

func (t L1005) Scan(e events.Event) Finding {
	res := Finding{}
	switch e.(type) {
	case *events.Open:
		ev := e.(*events.Open)
		if int(ev.Flags) != os.O_RDONLY {
			if strings.Contains(events.CStr(ev.Filename[:]), "/tmp/") || strings.Contains(events.CStr(ev.Pwd[:]), "tmp") {
				res.Found = true
				res.Level = LevelWarn
			}
			if strings.Contains(events.CStr(ev.Filename[:]), "/dev/shm") || strings.Contains(events.CStr(ev.Pwd[:]), "shm") {
				res.Found = true
				res.Level = LevelErr
			}
		}
	}
	return res
}
