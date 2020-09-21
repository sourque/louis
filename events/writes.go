package events

import (
	"bytes"
	"encoding/binary"
)

func (e Listen) Write(data []byte) (Event, error) {
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
	return e, err
}


func (e Open) Write(data []byte) (Event, error) {
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
	return e, err
}

func (e Exec) Write(data []byte) (Event, error) {
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
	return e, err
}


func (e Readline) Write(data []byte) (Event, error) {
	err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
	return e, err
}
