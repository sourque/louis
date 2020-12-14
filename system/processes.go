package system

import (
	"os"
)

func Kill(pid uint32) error {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	return p.Kill()
}
