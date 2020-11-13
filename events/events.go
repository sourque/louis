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
	IsPwd() bool
	FetchRetVal() int32
	SetRetVal(int32)
	SetPwd(string)
	FetchPwd() string
}

type eventBase struct {
	Uid    uint32
	Pid    uint32
	Ppid   uint32
	RetVal int32
	Ret    int32
	Pwd    [128]byte
}

type LogItem struct {
	Time time.Time
	Ev   Event
}

const (
	eventNormal = iota
	eventPwd
	eventRet
)

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
	return e.Ret == eventRet
}

func (e *eventBase) IsPwd() bool {
	return e.Ret == eventPwd
}

func (e *eventBase) FetchRetVal() int32 {
	return e.RetVal
}

func (e *eventBase) SetRetVal(val int32) {
	e.RetVal = val
}

func (e *eventBase) Write(data []byte) (Event, error) {
	newEvent := &eventBase{}
	err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), newEvent)
	return newEvent, err
}

func (e *eventBase) FetchPwd() string {
	pwd := CStr(e.Pwd[:])
	if pwd == "" {
		return "?"
	}
	return pwd
}

func (e *eventBase) SetPwd(tmp string) {
	for i := range tmp {
		e.Pwd[i] = tmp[i]
	}
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

func CStr(cString []byte) string {
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

func readEvents(event Event, evChan chan Event, ctx Ctx, m *bcc.Module, eventType string, normalHandler func(interface{})) {
	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte, 1000)

	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		ctx.Error <- newError(eventType, "failed to decode received data", err)
		return
	}

	go func() {
		pwdCache := make(map[uint32][]string)
		eventCache := make(map[uint32]Event)
		ctx.Load <- eventType
		ctx.LoadWg.Done()
		for {
			data := <-channel
			event, err := event.Write(data)
			if err != nil {
				ctx.Error <- newError(eventType, "failed to decode received data", err)
				continue
			}
			if event.IsRet() {

				caEvent, ok := eventCache[event.FetchPid()]
				if ok {
					caEvent.SetRetVal(event.FetchRetVal())
					event = caEvent
				}

				pwdVal, ok := pwdCache[event.FetchPid()]
				if ok {
					tmp := strings.Join(pwdVal, "/")
					tmp = strings.Replace(tmp, "\n", "\\n", -1)
					tmp = strings.TrimSpace(tmp)
					if len(tmp) > 124 {
						tmp = tmp[:124] + "..."
					}
					event.SetPwd(tmp)
				}

				evChan <- event
				delete(eventCache, event.FetchPid())
				delete(pwdCache, event.FetchPid())

			} else if event.IsPwd() {
				// fmt.Println("received new dir", CStr(event.Pwd[:]))
				pwdItems, ok := pwdCache[event.FetchPid()]
				if !ok {
					pwdItems = make([]string, 0)
				}
				pwdCache[event.FetchPid()] = append([]string{event.FetchPwd()}, pwdItems...)
			} else {
				if normalHandler != nil {
					normalHandler(event)
				} else {
					eventCache[event.FetchPid()] = event
				}
			}
		}
	}()

	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
