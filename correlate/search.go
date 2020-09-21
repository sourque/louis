package correlate

import (
    "errors"
    "strings"
    "reflect"

	"github.com/sourque/louis/events"
)

func findSession(es []events.LogItem) (string, error) {
	// os.Stat /dev/pts/X where uid is owner of pts
	return "", errors.New("findsession: no session found")
}

func findUid(es []events.LogItem, Uid uint32) []events.LogItem {
	return search(es, func(e events.LogItem) bool {
		return e.Data.FetchUid() == Uid
    })
}

func findPid(es []events.LogItem, Pid uint32) []events.LogItem {
	return search(es, func(e events.LogItem) bool {
        return e.Data.FetchPid() == Pid
    })
}

func ignoreEvent(es []events.LogItem, evTypes []string) []events.LogItem {
	// only allow a few of each event, most useful
	return search(es, func(e events.LogItem) bool {
        for _, evType := range evTypes {
    		if reflect.TypeOf(e.Data).String() == evType {
                return false
            }
        }
        return true
    })
}

func EventType(es []events.LogItem, eType string) []events.LogItem {
	foundEvents := []events.LogItem{}
	return foundEvents
}

func Bin(es []events.LogItem, Pid uint32) (string, error) {
	res := search(es, func(e events.LogItem) bool {
		if reflect.TypeOf(e.Data).String() == "events.Exec" {
            return e.Data.FetchPid() == Pid
        }
        return false
    })
    if len(res) == 0 {
        return "", errors.New("bin: no events found")
    } else if len(res) > 1 {
        return "", errors.New("bin: multiple events found")
    }
    return strings.Split(res[0].Data.(events.Exec).Argv, " ")[0], nil
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
