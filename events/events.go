// Package events provides event structures and data through eBPF.
package events

import (
	"bytes"
	"container/ring"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

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
	IsRet() bool
	FetchRet() int32
	SetRet(int32)
	FetchPwd() string
}

type eventBase struct {
	Uid    uint32
	Pid    uint32
	RetVal int32
	Ret    int32
	Pwd    [128]byte
}

type LogItem struct {
	Time time.Time
	Ev   Event
}

func (e *eventBase) Print() string {
	return "eventBase"
}

func (e *eventBase) FetchUid() uint32 {
	return e.Uid
}

func (e *eventBase) FetchPid() uint32 {
	return e.Pid
}

func (e *eventBase) IsRet() bool {
	return e.Ret == 1
}

func (e *eventBase) FetchRet() int32 {
	return e.RetVal
}

func (e *eventBase) SetRet(val int32) {
	e.RetVal = val
}

func (e *eventBase) Write(data []byte) (Event, error) {
	newEvent := &eventBase{}
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, newEvent)
	return newEvent, err
}

func (e *eventBase) FetchPwd() string {
	pwd := ReadCString(e.Pwd[:])
	if pwd == "" {
		return "?"
	}
	return pwd
}

// Contains the most recent 1000 events
var EventLog = ring.New(1000)

// logEvent writes the given event to the EventLog.
func Log(e Event) {
	EventLog.Value = LogItem{
		Time: time.Now(),
		Ev:   e,
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
		return string(cString[:]) + "..."
	}
	return string(cString[:byteIndex])
}

func newError(eventType, errorMsg string, err error) string {
	return eventType + ": " + errorMsg + ": " + err.Error()
}

func readEvents(event Event, evChan chan Event, ctx Ctx, m *bcc.Module, tableId, eventType string) {
	table := bcc.NewTable(m.TableId(tableId), m)
	eventStaging := make(map[uint32]interface{})

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
			data := <-channel
			event, err := event.Write(data)
			if err != nil {
				ctx.Error <- newError(eventType, "failed to decode received data", err)
				continue
			}
			// Event contains return value
			if event.IsRet() {
				if e, ok := eventStaging[event.FetchPid()]; !ok {
					evChan <- event
				} else {
					ev := e.(Event)
					ev.SetRet(event.FetchRet())
					evChan <- ev
					delete(eventStaging, event.FetchPid())
				}
			} else {
				eventStaging[event.FetchPid()] = event
			}
		}
	}()
	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
