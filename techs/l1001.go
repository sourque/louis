package techs

import (
	"github.com/sourque/louis/correlate"
	"github.com/sourque/louis/events"
	"github.com/sourque/louis/system"
)

type L1001 struct {
	techBase
}

func (t L1001) Name() string {
	return "Listen from Non-Service account"
}

func (t L1001) Scan(e events.Event) Finding {
	res := Finding{}
	if uid := e.FetchUid(); uid == 0 || uid >= 1000 {
		res.Found = true
		res.Level = LevelWarn
	}
	return res
}

func (t L1001) Clean(e events.Event) error {
	foundEvents, err := correlate.EventType(correlate.Related(e), "events.Listen")
	if err != nil {
		return err
	}
	return system.Kill(foundEvents[len(foundEvents)-1].Ev.FetchPid())
}
