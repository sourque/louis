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
	FetchPwd() string
	FetchRetVal() int32
	FetchOther() interface{}
	IsRet() bool
	IsPwd() bool
	IsOther() bool
	SetPwd(string)
	SetRetVal(int32)
	SetOther([]interface{})
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
	eventOther
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

func (e *eventBase) IsOther() bool {
	return e.Ret == eventOther
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

func (e *eventBase) FetchOther() interface{} {
	return nil
}

func (e *eventBase) SetPwd(tmp string) {
	for i := range tmp {
		e.Pwd[i] = tmp[i]
	}
}

func (e *eventBase) SetOther(input []interface{}) {}

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

// readEvents provides a standard interface to read and parse events from a BPF map
// and correctly read values for each type of event reture value
func readEvents(event Event, evChan chan Event, ctx Ctx, m *bcc.Module, eventType string) {
	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte, 1000)

	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		ctx.Error <- newError(eventType, "failed to decode received data", err)
		return
	}

	go func() {
		pwdCache := make(map[uint32][]string)
		otherCache := make(map[uint32][]interface{})
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
					// Workaround for valid execve comm only on return
					switch event.(type) {
					case *Exec:
						tmpEventNew := event.(*Exec)
						tmpEventOld := caEvent.(*Exec)
						tmpEventOld.Comm = tmpEventNew.Comm
						caEvent = tmpEventOld
					}
					event = caEvent
				} else {
					// ctx.Error <- newError(eventType, "event didn't have an item in cache!", errors.New("event didn't have an item in event cache"))
				}
				if pwdVal, ok := pwdCache[event.FetchPid()]; ok {
					tmp := strings.Join(pwdVal, "/")
					if tmp[0] != '/' {
						tmp = "/" + tmp
					}
					tmp = strings.Replace(tmp, "\n", "\\n", -1)
					tmp = strings.TrimSpace(tmp)
					if len(tmp) >= 128 {
						tmp = tmp[:124] + "..."
					}
					event.SetPwd(tmp)
					delete(pwdCache, event.FetchPid())
				}
				if otherVal, ok := otherCache[event.FetchPid()]; ok {
					event.SetOther(otherVal)
					delete(otherCache, event.FetchPid())
				}
				evChan <- event
				delete(eventCache, event.FetchPid())
			} else if event.IsPwd() {
				pwdItems, ok := pwdCache[event.FetchPid()]
				if !ok {
					pwdItems = make([]string, 0)
				}
				pwdCache[event.FetchPid()] = append([]string{event.FetchPwd()}, pwdItems...)
			} else if event.IsOther() {
				otherItems, ok := otherCache[event.FetchPid()]
				if !ok {
					otherItems = make([]interface{}, 0)
				}
				otherCache[event.FetchPid()] = append([]interface{}{event.FetchOther()}, otherItems...)
			} else {
				eventCache[event.FetchPid()] = event
			}
		}
	}()

	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
