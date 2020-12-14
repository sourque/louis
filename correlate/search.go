package correlate

import (
	"errors"
	"reflect"
	"strings"

	"github.com/sourque/louis/events"
)

func findSession(es []events.LogItem) (string, error) {
	// os.Stat /dev/pts/X where uid is owner of pts
	return "", errors.New("findsession: no session found")
}

func findUid(es []events.LogItem, Uid uint32) []events.LogItem {
	return search(es, func(e events.LogItem) bool {
		return e.Ev.FetchUid() == Uid
	})
}

func findPid(es []events.LogItem, Pid uint32) []events.LogItem {
	return search(es, func(e events.LogItem) bool {
		return e.Ev.FetchPid() == Pid
	})
}

func ignoreEvent(es []events.LogItem, evTypes []string) []events.LogItem {
	// only allow a few of each event, most useful
	return search(es, func(e events.LogItem) bool {
		for _, evType := range evTypes {
			if reflect.TypeOf(e.Ev).String() == evType {
				return false
			}
		}
		return true
	})
}

func EventType(es []events.LogItem, eType string) ([]events.LogItem, error) {
	foundEvents := search(es, func(e events.LogItem) bool {
		if strings.Contains(reflect.TypeOf(e.Ev).String(), eType) {
			return true
		}
		return false
	})
	if len(foundEvents) == 0 {
		return foundEvents, errors.New("eventType: no events found")
	}
	return foundEvents, nil
}

func Bin(es []events.LogItem, Pid uint32) (string, error) {
	res := search(es, func(e events.LogItem) bool {
		if reflect.TypeOf(e.Ev).String() == "*events.Exec" {
			return e.Ev.FetchPid() == Pid
		}
		return false
	})
	if len(res) == 0 {
		return "", errors.New("bin: no events found")
	} else if len(res) > 1 {
		return "", errors.New("bin: multiple events found")
	}
	return strings.Split(events.CStr(res[0].Ev.(*events.Exec).Argv[:]), " ")[0], nil
}

func search(es []events.LogItem, searchFunc func(e events.LogItem) bool) []events.LogItem {
	foundEvents := []events.LogItem{}
	for _, e := range es {
		if searchFunc(e) {
			foundEvents = append(foundEvents, e)
		}
	}
	return foundEvents
}
