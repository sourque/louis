package analysis

import (
	"fmt"
	"time"
	"os/user"
	"strconv"

	. "github.com/logrusorgru/aurora"

	"github.com/sourque/louis/events"
	"github.com/sourque/louis/techs"
	"github.com/sourque/louis/correlate"
)

type Detection struct {
	Time      time.Time
	Level     int
	Tech      techs.Tech
	Dupe      *Detection
	Artifacts []events.LogItem
}

// "global" logs
// implement as analysis context
// use ring buffer
var FileCreateLog []string

func (d *Detection) Print() string {
	// Warning
	techName := BrightYellow(d.Tech.Name())
	switch d.Level {
	// Informational
	case 0:
		techName = BrightBlue(d.Tech.Name())
	// Important
	case 2:
		techName = BrightMagenta(d.Tech.Name())
	// Critical
	case 3:
		techName = BrightRed(d.Tech.Name())
	}
	return fmt.Sprintf("%s %d artifact(s) {%s}", techName, len(d.Artifacts), d.Time.Format("2006-01-02"))
}

func (d *Detection) Brief() string {
	// time range of artifacts.
	// tech type
	// user name
	u := &user.User{
		Username: "?",
	}
	if len(d.Artifacts) > 0 {
		u, _ = user.LookupId(strconv.Itoa(int(d.Artifacts[0].Data.FetchUid())))
	}
	return fmt.Sprintf("u(s): %s in PATH from X - X", u.Username)
}

func processTechs(e events.Event, ts []techs.Tech) ([]*Detection, error) {
	detections := []*Detection{}
	for _, t := range ts {
		res := t.Scan(e)
		if res.Found {
			det := &Detection{
				Time:      time.Now(),
				Level:     res.Level,
				Tech:      t,
				Artifacts: []events.LogItem{},
			}
			det.Dupe = isDetectionDupe(det)
			det.Artifacts = append(det.Artifacts, correlate.Summarize(correlate.Related(e))...)
			detections = append(detections, det)
		}
	}
	return detections, nil
}

func isDetectionDupe(d *Detection) *Detection {
	// find things with same Tech, if so, will be printed as additional info
	return &Detection{}
}
