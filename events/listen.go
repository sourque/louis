package events

import (
	"fmt"

	bpf "github.com/iovisor/gobpf/bcc"
)

type Listen struct {
	eventBase
	Addr     uint32
	Port     uint16
	SockType int16
	Backlog  int32
}

func (e Listen) Print() string {
	return fmt.Sprintf("Addr %d, Port %d", e.Addr, e.Port)
}

// Credit to https://blog.yadutaf.fr/2016/03/30/turn-any-syscall-into-event-introducing-ebpf-kernel-probes/
func ListenBPF(evChan chan Event, ctx Ctx) {
	eventType := "listen"
	m := bpf.NewModule(`
		#include <uapi/linux/ptrace.h>
		#include <net/inet_sock.h>

		struct listen_event_t {
			u32 uid;
			u32 pid;
			u32 addr;
			u16 port;
			s16 backlog;
			short socktype;
			} __attribute__((packed));

			BPF_PERF_OUTPUT(listen_events);

			int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock, int backlog) {
				struct listen_event_t event = {};

				if (!PT_REGS_RC(ctx))
					return 0;

				event.pid = bpf_get_current_pid_tgid();
				event.uid = bpf_get_current_uid_gid();

				// Cast types
				struct sock *sk = sock->sk;
				struct inet_sock *inet = inet_sk(sk);

				// Working values. You *need* to initialize them to give them "life" on the stack and use them afterward
				u32 addr = 0;
				u16 port = 0;

				// Pull in details. As 'inet_sk' is internally a type cast, we need to use 'bpf_probe_read'
				// read: load into 'laddr' 'sizeof(laddr)' bytes from address 'inet->inet_rcv_saddr'
				bpf_probe_read(&addr, sizeof(addr), &(inet->inet_rcv_saddr));
				bpf_probe_read(&port, sizeof(port), &(inet->inet_sport));

				event.backlog = backlog;
				event.socktype = sock->type;
				event.addr = (addr>>8) | (addr<<8);
				event.port = (port>>8) | (port<<8);

				listen_events.perf_submit(ctx, &event, sizeof(event));

				return 0;
			}
			`, []string{})
	defer m.Close()

	listenKprobe, err := m.LoadKprobe("kprobe__inet_listen")
	if err != nil {
		ctx.Error <- "listen: failed to load get_return_value: " + err.Error()
		return
	}

	err = m.AttachKprobe("inet_listen", listenKprobe, -1)
	if err != nil {
		ctx.Error <- "listen: failed to attach return_value: " + err.Error()
		return
	}


	var event Listen
	readEvents(event, evChan, ctx, m, "listen_events", eventType)
}
