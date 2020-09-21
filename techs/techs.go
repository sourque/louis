package techs

import (
	"github.com/sourque/louis/events"
)

const (
	levelNil  = 0
	levelWarn = 1
	levelErr  = 2
	levelCrit = 3
)

type Tech interface {
	Name() string
	Scan(events.Event) Finding
	Check() (bool, int)
	Clean()
	Mitigate()
}

type Finding struct {
	Found bool
	Level int
}
