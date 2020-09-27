package correlate

import (
	"reflect"

	"github.com/sourque/louis/events"
)

func Dedupe(es []events.LogItem) {
	// find dupes. dupe counter? or just remove? lulw
}

func CombineProc(es []events.LogItem) []events.LogItem {
	// merge execve/fork/clone/readline/etc into one logitem
	return es
}

func Summarize(es []events.LogItem) []events.LogItem {
	// only allow a few of each event, most useful

	// temporary-- open is just too noisy
	summarizedEvents := ignoreEvent(es, []string{"*events.Open"})

	summarizedEvents = CombineProc(summarizedEvents)

	// temporary length limit
	if len(summarizedEvents) > 10 {
		return summarizedEvents[len(summarizedEvents)-10:]
	}

	return summarizedEvents
}

func Related(e events.Event) []events.LogItem {
	// find related events that may or may not be marked malicious
	// prob going to be tough to write

	// if sudo/su event, check for changed pid?

	foundEvents := []events.LogItem{}
	es := events.GetAll()
	if reflect.TypeOf(e).String() == "*events.Open" {
		//	fmt.Println(Bin(es, e.FetchPid()))
	}
	foundEvents = findUid(es, e.FetchUid())
	return foundEvents
}

func InList(items []string, search string) bool {
	for _, item := range items {
		if item == search {
			return true
		}
	}
	return false
}
