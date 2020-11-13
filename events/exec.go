// This code is modified from iovisor/gobpf examples.

package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/iovisor/gobpf/bcc"
)

import "C"

const (
	argSize = 128
	commLen = 16
	maxArgs = 20
)

type Exec struct {
	eventBase
	Comm [commLen]byte
	Argv [argSize]byte
}

func (e Exec) Print() string {
	return fmt.Sprintf("%s -> %s", CStr(e.Comm[:]), CStr(e.Argv[:]))
}

var execSource = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct event_t {
	` + eventBaseStr + `
    char comm[` + strconv.Itoa(commLen) + `];
    char argv[` + strconv.Itoa(argSize) + `];
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct event_t *event)
{
    bpf_probe_read(event->argv, sizeof(event->argv), ptr);
    events.perf_submit(ctx, event, sizeof(struct event_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct event_t *event)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), event);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
	` + gatherStr + `

    __submit_arg(ctx, (void *)filename, &event);

    #pragma unroll
    for (int i = 1; i < ` + strconv.Itoa(maxArgs) + `; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &event) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &event);

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

	out:
    event.ret = 0;
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx) {
	` + gatherStr + `
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
	` + retStr + `
}
`

func ExecBPF(evChan chan Event, ctx Ctx) {
	m := bcc.NewModule(execSource, []string{})
	defer m.Close()

	fnName := bcc.GetSyscallFnName("execve")

	kprobe, err := m.LoadKprobe("syscall__execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load syscall__execve: %s\n", err)
		os.Exit(1)
	}

	// passing -1 for maxActive signifies to use the default
	// according to the kernel kprobes documentation
	if err := m.AttachKprobe(fnName, kprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach syscall__execve: %s\n", err)
		os.Exit(1)
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_execve")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	// passing -1 for maxActive signifies to use the default
	// according to the kernel kretprobes documentation
	if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach do_ret_sys_execve: %s\n", err)
		os.Exit(1)
	}

	table := bcc.NewTable(m.TableId("events"), m)

	channel := make(chan []byte, 1000)

	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	go func() {
		args := make(map[uint32][]string)
		ctx.Load <- "exec"
		ctx.LoadWg.Done()
		for {
			event := &Exec{}
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			if !event.IsRet() {
				argItems, ok := args[event.Pid]
				if !ok {
					argItems = make([]string, 0)
				}
				args[event.Pid] = append(argItems, CStr(event.Argv[:]))
			} else {
				argv, ok := args[event.Pid]
				if !ok {
					print("no arguments found (argv) for exec")
				} else {
					tmp := strings.Join(argv, " ")
					tmp = strings.Replace(tmp, "\n", "\\n", -1)
					tmp = strings.TrimSpace(tmp)
					if len(tmp) > 128 {
						tmp = tmp[:128]
					}
					for i := range tmp {
						event.Argv[i] = tmp[i]
					}
				}
				evChan <- event
				delete(args, event.Pid)
			}
		}
	}()

	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
