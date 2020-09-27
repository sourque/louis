package events

import (
	"fmt"

	"github.com/iovisor/gobpf/bcc"
)

type Open struct {
	eventBase
	Dfd      int16
	Filename [80]byte
	Str      [80]byte
}

func (e Open) Print() string {
	return fmt.Sprintf("Filename %s from path %s", e.Filename, e.Pwd)
}

func OpenBPF(evChan chan Event, ctx Ctx) {
	eventType := "open"

	m := bcc.NewModule(`
		#include <uapi/linux/ptrace.h>
		#include <linux/sched.h>
		#include <linux/fs.h>
		#include <linux/fs_struct.h>
		#include <linux/dcache.h>

		#define MAX_ITEMS 12

		struct open_event_t {
			u32 uid;
			u32 pid;
			int retval;
			int ret;
			char pwd[128];
			s16 dfd;
			char filename[80];
			char str[80];
		} __attribute__((packed));

		BPF_PERF_OUTPUT(open_events);

		int syscall__openat(struct pt_regs *ctx,
			int dfd,
			const char __user *filename,
			int flags,
			umode_t mode)
		{

			struct open_event_t event = {};

		    struct task_struct *task;
		    task = (struct task_struct *)bpf_get_current_task();

			bpf_probe_read_str(&event.pwd, sizeof(event.pwd), task->fs->pwd.dentry->d_name.name);

			event.pid = bpf_get_current_pid_tgid();
			event.uid = bpf_get_current_uid_gid();
			event.dfd = dfd;

			bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
			bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);
			open_events.perf_submit(ctx, &event, sizeof(event));

			return 0;
		}

		int do_ret_sys_openat(struct pt_regs *ctx)
		{
		    struct open_event_t event = {};
		    event.pid = bpf_get_current_pid_tgid() >> 32;
			event.ret = 1;
		    event.retval = PT_REGS_RC(ctx);
		    open_events.perf_submit(ctx, &event, sizeof(event));
		    return 0;
		}
	`, []string{})
	defer m.Close()

	fnName := bcc.GetSyscallFnName("openat")

	openKprobe, err := m.LoadKprobe("syscall__openat")
	if err != nil {
		ctx.Error <- newError(eventType, "failed to load get_return_value", err)
		return
	}

	err = m.AttachKprobe(fnName, openKprobe, -1)
	if err != nil {
		ctx.Error <- newError(eventType, "failed to attach return_value", err)
		return
	}

	kretprobe, err := m.LoadKprobe("do_ret_sys_openat")
	if err != nil {
		ctx.Error <- newError(eventType, "failed to load do_ret_sys_openat", err)
		return
	}

	if err := m.AttachKretprobe(fnName, kretprobe, -1); err != nil {
		ctx.Error <- newError(eventType, "failed to attach do_ret_sys_openat", err)
		return
	}

	event := &Open{}
	readEvents(event, evChan, ctx, m, "open_events", eventType)
}
