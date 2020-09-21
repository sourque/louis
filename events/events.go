// Package events provides event structures and data through eBPF.
package events

import (
	"container/ring"
	"fmt"
	"reflect"
	"time"
	"strings"
	"sync"
	"bytes"
	"github.com/iovisor/gobpf/bcc"
)

type Ctx struct {
	LoadWg *sync.WaitGroup
	Load   chan string
	Error  chan string
	Quit   chan bool
}

type Event interface {
	Print() string
	Write([]byte) (Event, error)
	FetchUid() uint32
	FetchPid() uint32
}

type eventBase struct {
	Uid uint32
	Pid uint32
}

type LogItem struct {
	Time time.Time
	Data Event
}

func (e eventBase) FetchUid() uint32 {
	return e.Uid
}

func (e eventBase) FetchPid() uint32 {
	return e.Pid
}

// Contains the most recent 1000 events
var EventLog = ring.New(1000)

// logEvent writes the given event to the EventLog.
func Log(e Event) {
	EventLog.Value = LogItem{
		Time: time.Now(),
		Data: e,
	}
	EventLog = EventLog.Next()
}

func GetAll() []LogItem {
	allEvents := []LogItem{}
	EventLog.Do(func(e interface{}) {
		if reflect.TypeOf(e) == reflect.TypeOf(LogItem{}) {
			allEvents = append(allEvents, e.(LogItem))
		}
	})
	return allEvents
}

func NewContext() Ctx {
	return Ctx{
		LoadWg: &sync.WaitGroup{},
		Load:   make(chan string),
		Error:  make(chan string),
		Quit:   make(chan bool),
	}
}

func TypeHeader(e Event) string {
	return strings.Split(fmt.Sprintf("%T", e), ".")[1]
}

func ReadCString(cString []byte) string {
	if len(cString) == 0 {
		return ""
	}
	byteIndex := bytes.IndexByte(cString, 0)
	if byteIndex == -1 {
		return string(cString[:len(cString)]) + "..."
	}
	return string(cString[:byteIndex])
}

func newError(eventType, errorMsg string, err error) string {
	return eventType + ": " + errorMsg + ": " + err.Error()
}

func readEvents(event Event, evChan chan Event, ctx Ctx, m *bcc.Module, tableId, eventType string) {

	table := bcc.NewTable(m.TableId(tableId), m)

	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		ctx.Error <- newError(eventType, "failed to init perf map", err)
		return
	}

	ctx.Load <- eventType
	ctx.LoadWg.Done()
	go func() {
	for {
		data := <- channel
		event, err := event.Write(data)
		if err != nil {
			ctx.Error <- newError(eventType, "failed to decode received data", err)
			continue
		}
		evChan <- event
		}

	}()
	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
