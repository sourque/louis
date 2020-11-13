package analysis

import (
	"container/ring"
	"reflect"
	"time"

	"github.com/sourque/louis/events"
	"github.com/sourque/louis/techs"
)

type Detection struct {
	Time      time.Time
	Level     int
	Tech      techs.Tech
	Dupe      *Detection
	Artifacts []events.LogItem
}

type LogItem struct {
	Time time.Time
	Det  Detection
}

// Contains the most recent 1000 events
var DetectionLog = ring.New(1000)

// logEvent writes the given event to the EventLog.
func Log(d Detection) {
	DetectionLog.Value = LogItem{
		Time: time.Now(),
		Det:  d,
	}
	DetectionLog = DetectionLog.Next()
}

func GetAll() []LogItem {
	allEvents := []LogItem{}
	DetectionLog.Do(func(e interface{}) {
		if reflect.TypeOf(e) == reflect.TypeOf(LogItem{}) {
			allEvents = append(allEvents, e.(LogItem))
		}
	})
	return allEvents
}

func Exec(e *events.Exec) ([]*Detection, error) {
	detections := []*Detection{}
	return detections, nil
}

func Listen(e *events.Listen) ([]*Detection, error) {
	return processTechs(e, []techs.Tech{
		techs.L1001{},
	})
}

func Open(e *events.Open) ([]*Detection, error) {
	return processTechs(e, []techs.Tech{
		techs.L1002{},
		techs.L1004{},
		techs.L1005{},
		techs.T1098{},
	})
}

func Readline(e *events.Readline) ([]*Detection, error) {
	detections := []*Detection{}
	return detections, nil
}
