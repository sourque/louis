package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/sourque/louis/analysis"
	"github.com/sourque/louis/events"
	"github.com/sourque/louis/output"

	"github.com/spf13/cobra"
)

var (
	passive     bool
	verbose     bool
	mitigate    bool
	duplicates  bool
	interactive bool
	ignoreList  []string
)

const (
	version = "0.0.1"
)

// monitor
// scan (default values to investigate)
// mitigate (run through all mitigations, mitigate.Check() mitigate.Run())
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

	cmdScan := &cobra.Command{
		Use:   "scan",
		Short: "scan for malicious activity in common locations",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	cmdMitigate := &cobra.Command{
		Use:   "mitigate",
		Short: "iterate through each known vulnerability and remediate",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	cmdVersion := &cobra.Command{
		Use:   "version",
		Short: "print louis version",
		Run: func(cmd *cobra.Command, args []string) {
			output.Note("louis version", version)
		},
	}

	rootCmd := &cobra.Command{
		Use: "louis",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			output.Init()
			output.SetVerbose(verbose)
		},
	}
	rootCmd.PersistentFlags().BoolVarP(&passive, "passive", "p", false, "don't perform any intrusive action")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.AddCommand(cmdMonitor, cmdScan, cmdMitigate, cmdVersion)
	rootCmd.Execute()
}

func louisMonitor() {
	output.Positive("Welcome to louis :)")

	// Quit when program receives CTRL-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Events context (contains output/error channels and *sync.WaitGroup)
	evCtx := events.NewContext()
	evChan := make(chan events.Event)

	// List of implemented sources
	sourceList := []func(chan events.Event, events.Ctx){
		events.ExecBPF,
		events.ReadlineBPF,
		events.OpenBPF,
		events.ListenBPF,
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

	go func() {
		output.Info("Beginning monitoring loop...")
		for {
			var detections []*analysis.Detection
			var err error

			select {

			case module := <-evCtx.Load:
				output.Positive("Loaded module:", module)
			case <-evLoaded:
				output.Info("All modules loaded!")
			case err := <-evCtx.Error:
				output.Negative("Error:", err)

			case ev := <-evChan:
				// automatically detect and cast type? use wrapper struct with analysis function embedded?
				events.Log(ev)
				switch ev.(type) {
				case *events.Exec:
					detections, err = analysis.Exec(ev.(*events.Exec))
				case *events.Readline:
					detections, err = analysis.Readline(ev.(*events.Readline))
				case *events.Listen:
					detections, err = analysis.Listen(ev.(*events.Listen))
				case *events.Open:
					detections, err = analysis.Open(ev.(*events.Open))
				}
				if typeHeader := events.TypeHeader(ev); !output.IsIgnored(ignoreList, typeHeader) {
					output.Event(typeHeader, fmt.Sprintf("%s {%d} (%d) [%d]", ev.Print(), ev.FetchRet(), ev.FetchUid(), ev.FetchPid()))
				}
			}

			// Handle detection results
			if err != nil {
				output.Error(err)
				continue
			}
			for _, det := range detections {
				analysis.Log(*det)
				if det.Dupe.Tech != nil && duplicates {
					output.Warn("DUPLICATE!", det.Print())
				} else {
					output.Warn(det.Print())
					output.Tabber(1)
					output.Negative(det.Brief())
					for i := len(det.Artifacts) - 1; i >= 0; i-- {
						art := det.Artifacts[i]
						output.EventLog(art.Time, events.TypeHeader(art.Ev), art.Ev.Print())
					}

					if !passive {
						output.Positive("Cleaning", det.Tech)
						if det.Tech.Clean != nil {
							det.Tech.Clean()
						}
						if mitigate && det.Tech.Mitigate != nil {
							output.Positive("Mitigating", det.Tech)
							det.Tech.Mitigate()
						}
					}
				}
				output.Tabber(0)

				// [!] Event detected!
				//	 [*] T1089 Malcious key added (/root/.ssh/authorized_keys)
				//		- FileCreate on authorized_keys
				//   [*] TXXX Backdoor user added (bobbie)
				//		- FileModified on authorized_keys (ssh-rsa RTjh95d...)
				//	 [+] Mitigating...
				//		--> File authorized_keys moved to quarantine
				//		--> User bobbie locked out

			}
		}
	}()

	<-sig
	output.Info("Waiting for monitoring goroutines to quit...")
	evCtx.Quit <- true
}
