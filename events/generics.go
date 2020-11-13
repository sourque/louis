package events

import (
	"bytes"
	"encoding/binary"
)

// generic event types for Findings

type File struct {
	eventBase
	Filename string
}

type Process struct {
	eventBase
}

type User struct {
	eventBase
}

// insert sobbing here

func WriteEventData(newEvent Event, data []byte) (Event, error) {
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, newEvent)
	return newEvent, err
}

func (e *Exec) Write(data []byte) (Event, error) {
	newEvent := &Exec{}
	return WriteEventData(newEvent, data)
}

func (e *Listen) Write(data []byte) (Event, error) {
	newEvent := &Listen{}
	return WriteEventData(newEvent, data)
}

func (e *Open) Write(data []byte) (Event, error) {
	newEvent := &Open{}
	return WriteEventData(newEvent, data)
}

func (e *Readline) Write(data []byte) (Event, error) {
	newEvent := &Readline{}
	return WriteEventData(newEvent, data)
}
