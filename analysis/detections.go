package analysis

import (
	"github.com/sourque/louis/events"
	"github.com/sourque/louis/techs"
)

func Exec(e events.Exec) ([]*Detection, error) {
	detections := []*Detection{}
	return detections, nil
}

func Readline(e events.Readline) ([]*Detection, error) {
	detections := []*Detection{}
	return detections, nil
}

func Open(e events.Open) ([]*Detection, error) {
	return processTechs(e, []techs.Tech{
		techs.L1002{},
		techs.T1098{},
	})
}

func Listen(e events.Listen) ([]*Detection, error) {
	return processTechs(e, []techs.Tech{
		techs.L1001{},
	})
}
