package techs

import (
	"github.com/sourque/louis/events"
)

// L1001 is non-system users or unusual binaries opening a listening socket.
type L1001 struct{}

func (t L1001) Name() string {
	return "Listen from Non-Service account"
}

func (t L1001) Scan(e events.Event) Finding {
	res := Finding{}
	if uid := e.FetchUid(); uid == 0 || uid >= 1000 {
		res.Found = true
		res.Level = levelWarn
	}
	return res
}

func (t L1001) Check() (bool, int) {
	return true, 1
}

func (t L1001) Clean() {

}
func (t L1001) Mitigate() {

}
