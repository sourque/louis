package output

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strings"
	"time"

	. "github.com/logrusorgru/aurora"
)

var (
	logger       *log.Logger
	tabs         string
	Verbose      bool
	syslogWriter *syslog.Writer
	Syslog       bool
)

func Init() {
	if Syslog {
		var err error
		syslogWriter, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "louis")
		if err != nil {
			log.Fatalln("failed to initialize syslog writer:", err.Error())
		}
		logger = log.New(syslogWriter, "", 0)
	} else {
		logger = log.New(os.Stdout, "", 0)
	}
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

func Leveled(level int, a ...interface{}) {
	switch level {
	// Important
	case 1:
		Crit(a...)
	// Very Important
	case 2:
		Alert(a...)
	// Default, Warning
	default:
		Warning(a...)
	}
}

func Alert(a ...interface{}) {
	if Verbose {
		if Syslog {
			syslogWriter.Alert(fmt.Sprintln(a...))
		} else {
			logger.Printf("%s%s %s", tabs, BrightMagenta("[!]"), fmt.Sprintln(a...))
		}
	}
}

func Crit(a ...interface{}) {
	if Syslog {
		syslogWriter.Crit(fmt.Sprintln(a...))
	} else {
		logger.Printf("%s%s %s", tabs, Red("[!]"), fmt.Sprintln(a...))
	}
}

func Err(a ...interface{}) {
	if Syslog {
		syslogWriter.Err(fmt.Sprintln(a...))
	} else {
		logger.Printf("%s%s %s", tabs, BrightRed("[!]"), fmt.Sprintln(a...))
	}
}

func Warning(a ...interface{}) {
	if Syslog {
		syslogWriter.Warning(fmt.Sprintln(a...))
	} else {
		logger.Printf("%s%s %s", tabs, Yellow("[~]"), fmt.Sprintln(a...))
	}
}

func Info(a ...interface{}) {
	if Verbose {
		if Syslog {
			syslogWriter.Info(fmt.Sprintln(a...))
		} else {
			logger.Printf("%s%s %s", tabs, BrightCyan("[~]"), fmt.Sprintln(a...))
		}
	}
}

func Notice(a ...interface{}) {
	if Syslog {
		syslogWriter.Notice(fmt.Sprintln(a...))
	} else {
		logger.Printf("%s%s %s", tabs, BrightCyan("[!]"), fmt.Sprintln(a...))
	}
}

func Positive(a ...interface{}) {
	if Syslog {
		syslogWriter.Info(fmt.Sprintln(a...))
	} else {
		logger.Printf("%s%s %s", tabs, Green("[+]"), fmt.Sprintln(a...))
	}
}

func Negative(a ...interface{}) {
	if Syslog {
		syslogWriter.Warning("-> " + fmt.Sprintln(a...))
	} else {
		logger.Printf("%s%s %s", tabs, BrightRed("[!]"), fmt.Sprintln(a...))
	}
}

func Event(eventType string, a ...interface{}) {
	if Verbose {
		if Syslog {
			syslogWriter.Info(eventType + " " + fmt.Sprintln(a...))
		} else {
			logger.Printf("%s%s %s %s", tabs, BrightCyan("[~]"), BrightBlue(eventType), fmt.Sprintln(a...))
		}
	}
}

func EventLog(logTime time.Time, eventType string, a ...interface{}) {
	if !Syslog {
		logger.Printf("%s%s %s %s %s", tabs, BrightCyan("->"), logTime.Format("3:04:05 PM"), BrightBlue(eventType), fmt.Sprintln(a...))
	}
}

func IsIgnored(ignoreList []string, eventType string) bool {
	for _, l := range ignoreList {
		if strings.Contains(strings.ToLower(eventType), strings.ToLower(l)) {
			return true
		}
	}
	return false
}
