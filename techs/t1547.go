package techs

import (
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
	return res
}
