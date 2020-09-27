package techs

import (
	"strings"

	"github.com/sourque/louis/correlate"
	"github.com/sourque/louis/events"
)

// L1002 is non-trusted users or programs reading /etc/shadow.
type T1098 struct{}

func (t T1098) Name() string {
	return "Account Manipulation: SSH Authorized Keys"
}

func (t T1098) Scan(e events.Event) Finding {
	res := Finding{}
	switch e.(type) {
	// should be Write
	// catch return value???
	case *events.Open:
		ev := e.(*events.Open)
		fileName := events.ReadCString(ev.Filename[:])
		if strings.Contains(fileName, "authorized_keys") {
			owner, err := correlate.Owner(fileName)
			if err != nil {
				// file not found
				// fmt.Println("t1098: error in fetching file owner:", err)
				res.Found = true
				res.Level = levelWarn
				return res
			}
			if owner != ev.Uid {
				res.Found = true
				res.Level = levelCrit
			}
		}
	}
	return res
}

func (t T1098) Check() (bool, int) {
	return true, levelNil
}

func (t T1098) Clean() {
}

func (t T1098) Mitigate() {
}
