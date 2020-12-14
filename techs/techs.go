package techs

import (
	"github.com/sourque/louis/events"
)

const (
	LevelNil = iota
	LevelWarn
	LevelErr
	LevelCrit
)

type Tech interface {
	Name() string

	// Scan handles input stream of events
	Scan(events.Event) Finding
	// Hunt takes no parameters and looks for evidence of exploitation
	Hunt() (Finding, error)
	// Clean responds to events detected by Scan or Hunt by removing artifacts
	Clean(events.Event) error
	// Check determines if vulnerability mitigation is required
	Check() (Finding, error)
	// Mitigation mitigates the vulnerability
	Mitigate() error
}

type techBase struct{}

func (t techBase) Hunt() (Finding, error) {
	return Finding{}, nil
}

func (t techBase) Clean(e events.Event) error {
	return nil
}

func (t techBase) Check() (Finding, error) {
	return Finding{}, nil
}

func (t techBase) Mitigate() error {
	return nil
}

type Finding struct {
	Ev    events.Event
	Found bool
	Level int
}

func All() []Tech {
	return []Tech{
		L1001{},
		L1002{},
		L1003{},
		L1004{},
		L1005{},
		T1098{},
		T1547{},
	}
}
