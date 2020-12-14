package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/sourque/louis/analysis"
	"github.com/sourque/louis/events"
	"github.com/sourque/louis/output"
	"github.com/sourque/louis/techs"

	"github.com/spf13/cobra"
)

var (
	active      bool
	mitigate    bool
	duplicates  bool
	interactive bool
	ignoreList  []string
)

const (
	version = "0.0.5"
)

func main() {
	cmdMonitor := &cobra.Command{
		Use:     "monitor",
		Aliases: []string{"m", "mon", "eyes"},
		Short:   "actively monitor for malicious action",
		Run: func(cmd *cobra.Command, args []string) {
			louisMonitor()
		},
	}

	cmdMonitor.Flags().BoolVarP(&mitigate, "mitigate", "m", false, "attempt to mitigate detected techniques")
	cmdMonitor.Flags().BoolVarP(&duplicates, "duplicates", "d", false, "show duplicate detections")
	cmdMonitor.Flags().StringSliceVarP(&ignoreList, "ignore", "i", []string{}, "don't show certain event types in verbose mode (ex. -i open)")

	cmdHunt := &cobra.Command{
		Use:     "hunt",
		Aliases: []string{"h", "uwu"},
		Short:   "hunt for existing malicious activity",
		Run: func(cmd *cobra.Command, args []string) {
			louisHunt()
		},
	}

	cmdHunt.Flags().BoolVarP(&mitigate, "mitigate", "m", false, "attempt to mitigate detected techniques")

	cmdMitigate := &cobra.Command{
		Use:     "mitigate",
		Aliases: []string{"mit", "cybpat"},
		Short:   "mitigate all known vulnerabilities",
		Run: func(cmd *cobra.Command, args []string) {
			louisMitigate()
		},
	}

	cmdVersion := &cobra.Command{
		Use:   "version",
		Short: "print louis version",
		Run: func(cmd *cobra.Command, args []string) {
			output.Notice("louis version", version)
		},
	}

	rootCmd := &cobra.Command{
		Use: "louis",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			output.Init()
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&active, "active", "a", false, "counter detected malicious activity (dangerous, may clobber)")
	rootCmd.PersistentFlags().BoolVarP(&output.Verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&output.Syslog, "syslog", "s", false, "output to syslog")
	rootCmd.AddCommand(cmdMonitor, cmdHunt, cmdMitigate, cmdVersion)
	rootCmd.Execute()
}

func louisMonitor() {
	output.Info("Welcome to louis :)")

	// Quit when program receives CTRL-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Events context (contains output/error channels and *sync.WaitGroup)
	evCtx := events.NewContext()
	evChan := make(chan events.Event)

	// List of implemented sources
	sourceList := []func(chan events.Event, events.Ctx){
		events.ExecBPF,
		events.ListenBPF,
		events.OpenBPF,
		events.ReadlineBPF,
	}

	// Load each eBPF module
	output.Info("Loading eBPF modules...")
	evCtx.LoadWg.Add(len(sourceList))
	for _, sourceFunc := range sourceList {
		go sourceFunc(evChan, evCtx)
	}

	evLoaded := make(chan bool)
	go func() {
		evCtx.LoadWg.Wait()
		evLoaded <- true
	}()

	// Handle output from BPF modules
	go func() {
		output.Info("Beginning monitoring loop...")
		for {
			var detections []*analysis.Detection
			var err error

			select {

			case module := <-evCtx.Load:
				output.Info("Loaded module:", module)
			case <-evLoaded:
				output.Info("All modules loaded!")
			case err := <-evCtx.Error:
				output.Negative("Error:", err)

			case ev := <-evChan:
				events.Log(ev)
				switch ev.(type) {
				case *events.Exec:
					detections, err = analysis.Exec(ev.(*events.Exec))
				case *events.Listen:
					detections, err = analysis.Listen(ev.(*events.Listen))
				case *events.Open:
					detections, err = analysis.Open(ev.(*events.Open))
				case *events.Readline:
					detections, err = analysis.Readline(ev.(*events.Readline))
				}
				if typeHeader := events.TypeHeader(ev); !output.IsIgnored(ignoreList, typeHeader) {
					output.Event(typeHeader, fmt.Sprintf("%s {ret: %d} (uid: %d) [pid: %d]", ev.Print(), ev.FetchRetVal(), ev.FetchUid(), ev.FetchPid()))
				}
			}

			// Handle detection results
			if err != nil {
				output.Err(err)
				continue
			}
			for _, det := range detections {
				analysis.Log(*det)
				if det.Dupe.Tech != nil {
					if duplicates {
						output.Leveled(det.Level, "DUPLICATE!", det.Print())
					}
				} else {
					output.Leveled(det.Level, det.Print())
					output.Tabber(1)
					output.Negative(det.Brief())
					for i := len(det.Artifacts) - 1; i >= 0; i-- {
						art := det.Artifacts[i]
						output.EventLog(art.Time, events.TypeHeader(art.Ev), art.Ev.Print())
					}
				}

				if active {
					// Clean most recent artifact
					if len(det.Artifacts) > 0 {
						output.Positive("Cleaning:", det.Tech.Name())
						if err := det.Tech.Clean(det.Artifacts[0].Ev); err != nil {
							output.Negative("Cleaning failed:", err.Error())
						}
					}
					if mitigate {
						output.Positive("Mitigating", det.Tech)
						det.Tech.Mitigate()
					}
				}
				output.Tabber(0)
			}
		}
	}()

	<-sig
	output.Info("Waiting for monitoring routines to quit...")
	evCtx.Quit <- true
}

func louisHunt() {
	ts := techs.All()
	for _, t := range ts {
		output.Info("Hunting:", t.Name())
		if res, err := t.Hunt(); err != nil {
			output.Negative("Error in hunting:", t.Name()+":", err.Error())
		} else if res.Found {
			output.Positive("Found:", t.Name(), res.Ev.Print())
			if active {
				t.Clean(res.Ev)
				if mitigate {
					t.Mitigate()
				}
			}
		}
	}
}

func louisMitigate() {
	ts := techs.All()
	for _, t := range ts {
		output.Info("Checking:", t.Name())
		if res, err := t.Check(); err != nil {
			output.Negative("Error in checking for mitigation:", t.Name()+":", err.Error())
		} else if res.Found {
			if !active {
				output.Positive("Mitigation possible:", t.Name())
				if res.Ev != nil {
					output.Tabber(1)
					output.Negative(res.Ev.Print)
					output.Tabber(0)
				}
			} else {
				output.Info("Mitigating:", t.Name())
				if err := t.Mitigate(); err != nil {
					output.Negative("Error in mitigating:", t.Name()+":", err.Error())
				} else {
					output.Positive("Mitigated:", t.Name())
				}
			}
		}
	}
}
