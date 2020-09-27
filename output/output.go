package output

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	. "github.com/logrusorgru/aurora"
)

var (
	logger  *log.Logger
	tabs    string
	verbose bool
)

func Init() {
	logger = log.New(os.Stdout, "", 0)
}

func SetVerbose(v bool) {
	verbose = v
}

func Time(t time.Time) string {
	return t.Format("03:04:05 PM")
}

// pretty-print output
// buffered prompt at bottom that /rs ?? how am i going to do that

func Tabber(tabnum int) {
	tabs = ""
	for i := 0; i < tabnum; i++ {
		tabs += "\t"
	}
}

func Error(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, Red("[!]"), fmt.Sprintln(a...))
}

func Warn(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, Yellow("[~]"), fmt.Sprintln(a...))
}

func Info(a ...interface{}) {
	if verbose {
		logger.Printf("%s%s %s", tabs, BrightCyan("[~]"), fmt.Sprintln(a...))
	}
}

func Note(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, BrightCyan("[!]"), fmt.Sprintln(a...))
}

func Positive(a ...interface{}) {
	if verbose {
		logger.Printf("%s%s %s", tabs, Green("[+]"), fmt.Sprintln(a...))
	}
}

func Negative(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, BrightRed("[!]"), fmt.Sprintln(a...))
}

func Event(eventType string, a ...interface{}) {
	if verbose {
		logger.Printf("%s%s %s %s", tabs, BrightCyan("[~]"), BrightBlue(eventType), fmt.Sprintln(a...))
	}
}

func EventLog(logTime time.Time, eventType string, a ...interface{}) {
	logger.Printf("%s%s %s %s %s", tabs, BrightCyan("->"), logTime.Format("3:04:05 PM"), BrightBlue(eventType), fmt.Sprintln(a...))
}

func IsIgnored(ignoreList []string, eventType string) bool {
	for _, l := range ignoreList {
		if strings.Contains(strings.ToLower(eventType), strings.ToLower(l)) {
			return true
		}
	}
	return false
}
