package events

import (
	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"
)

type Open struct {
	eventBase
	Dfd      int16
	Filename [80]byte
	Str      [80]byte
}

func (e Open) Print() string {
	return fmt.Sprintf("Filename %s", e.Filename)
}


func OpenBPF(evChan chan Event, ctx Ctx) {
	eventType := "open"

	m := bpf.NewModule(`
		#include <uapi/linux/ptrace.h>

		struct open_event_t {
			u32 uid;
			u32 pid;
			s16 dfd;
			char filename[80];
			char str[80];
		} __attribute__((packed));

		BPF_PERF_OUTPUT(open_events);

		int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd,
			const char __user *filename, int flags,
			umode_t mode) {
				struct open_event_t event = {};

				event.pid = bpf_get_current_pid_tgid();
				event.uid = bpf_get_current_uid_gid();
				event.dfd = dfd;

				bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
				bpf_probe_read_str(&event.filename, sizeof(event.filename), filename);
				open_events.perf_submit(ctx, &event, sizeof(event));

				return 0;
		}
	`, []string{})
	defer m.Close()

	openKprobe, err := m.LoadKprobe("syscall__trace_entry_openat")
	if err != nil {
		ctx.Error <- newError(eventType, "failed to load get_return_value", err)
		return
	}

	err = m.AttachKprobe(bpf.GetSyscallFnName("openat"), openKprobe, -1)
	if err != nil {
		ctx.Error <- newError(eventType, "failed to attach return_value", err)
		return
	}

	var event Open
	readEvents(event, evChan, ctx, m, "open_events", eventType)
}
