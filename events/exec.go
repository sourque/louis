// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This code is almost entirely copied from iovisor/gobpf examples.

package events

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

type EventType int32

const (
	eventArg EventType = iota
	eventRet
)

type Exec struct {
	eventBase
	Ppid   string
	Comm   string
	Type   int32
	Argv   string
	RetVal int32
}

func (e Exec) Print() string {
	return fmt.Sprintf("%s", e.Argv)
}

type execveEvent struct {
	Pid    uint64
	Ppid   uint64
	Comm   [16]byte
	Type   int32
	Argv   [128]byte
	RetVal int32
}

const execSource string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG, // event arguments
    EVENT_RET, // event return value
};

struct data_t {
    u64 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u64 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the getPpid function as a fallback in those cases.
    // See https://github.com/iovisor/bcc/issues/1883.
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAX_ARGS; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);

	out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the getPpid function as a fallback in those cases.
    // See https://github.com/iovisor/bcc/issues/1883.
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
`

// getPpid is a fallback to read the parent PID from /proc.
// Some kernel versions, like 4.13.0 return 0 getting the parent PID
// from the current task, so we need to use this fallback to have
// the parent PID in any kernel.
func getPpid(pid uint64) uint64 {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/status", pid), os.O_RDONLY, os.ModePerm)
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		text := sc.Text()
		if strings.Contains(text, "PPid:") {
			f := strings.Fields(text)
			i, _ := strconv.ParseUint(f[len(f)-1], 10, 64)
			return i
		}
	}
	return 0
}

func ExecBPF(evChan chan Event, ctx Ctx) {
	maxArgs := 20

	m := bpf.NewModule(strings.Replace(execSource, "MAX_ARGS", strconv.Itoa(maxArgs), -1), []string{})
	defer m.Close()

	fnName := bpf.GetSyscallFnName("execve")

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

	table := bpf.NewTable(m.TableId("events"), m)

	channel := make(chan []byte, 1000)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	go func() {
		args := make(map[uint64][]string)
		ctx.Load <- "exec"
		ctx.LoadWg.Done()
		for {
			data := <-channel

			var event execveEvent
			err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}

			if eventArg == EventType(event.Type) {
				e, ok := args[event.Pid]
				if !ok {
					e = make([]string, 0)
				}
				argv := (*C.char)(unsafe.Pointer(&event.Argv))

				e = append(e, C.GoString(argv))
				args[event.Pid] = e
			} else {
				comm := C.GoString((*C.char)(unsafe.Pointer(&event.Comm)))

				argv, ok := args[event.Pid]
				if !ok {
					continue
				}

				p := &Exec{
					Ppid:   "?",
					Comm:   comm,
					RetVal: event.RetVal,
				}

				p.Pid = uint32(event.Pid)

				if event.Ppid == 0 {
					event.Ppid = getPpid(event.Pid)
				}

				if event.Ppid != 0 {
					p.Ppid = strconv.FormatUint(event.Ppid, 10)
				}

				p.Argv = strings.Join(argv, " ")
				p.Argv = strings.TrimSpace(strings.Replace(p.Argv, "\n", "\\n", -1))

				evChan <- p
				delete(args, event.Pid)
			}
		}
	}()

	perfMap.Start()
	<-ctx.Quit
	perfMap.Stop()
}
