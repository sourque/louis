package analysis

import (
	"fmt"
	"os/user"
	"strconv"
	"time"

	"github.com/sourque/louis/correlate"
	"github.com/sourque/louis/events"
	"github.com/sourque/louis/output"
	"github.com/sourque/louis/techs"
)

// Infractions (detections above warn) by user IDs
var naughtyList = make(map[uint32]int)

func (d *Detection) Print() string {
	return fmt.Sprintf("%s - %s", d.Tech.Name(), d.Time.Format("2006-01-02"))
}

func (d *Detection) Brief() string {
	// time range of artifacts.
	// tech type
	// user name
	u := &user.User{
		Username: "?",
	}
	if len(d.Artifacts) > 0 {
		u, _ = user.LookupId(strconv.Itoa(int(d.Artifacts[0].Ev.FetchUid())))
		startDate := output.Time(d.Artifacts[0].Time)
		endDate := output.Time(d.Artifacts[len(d.Artifacts)-1].Time)
		return fmt.Sprintf("%s in %s from %s - %s", u.Username, d.Artifacts[0].Ev.FetchPwd(), startDate, endDate)
	}
	return fmt.Sprintf("No artifacts added! This usually happens when an event that triggered a warning is filtered out due to verbosity.")
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
	allDets := GetAll()
	if len(allDets) > 0 {
		lastDet := allDets[len(allDets)-1]
		if lastDet.Det.Tech == d.Tech {
			return &lastDet.Det
		}
	}
	return &Detection{}
}
