package events

import (
	"strconv"
)

var (
	eventBaseStr = `
	u32 uid;
	u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
	u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
	int retval;
	int ret;
	char pwd[128];
	`

	submitArgStr = `
	`

	submitNormal = `
	event.ret = ` + strconv.Itoa(eventNormal) + `;
    events.perf_submit(ctx, &event, sizeof(struct event_t));
	return 0;
	`

	reqFunctions = `
	#include <linux/fs.h>
	#include <linux/fs_struct.h>
	#include <linux/dcache.h>
	BPF_PERF_OUTPUT(events);
	`

	getPwd = `
	struct dentry* walker = task->fs->pwd.dentry;

    for (int i = 1; i < ` + strconv.Itoa(maxArgs) + `; i++) {
		bpf_probe_read_str(&event.pwd, sizeof(event.pwd), walker->d_name.name);

		event.ret = ` + strconv.Itoa(eventPwd) + `;
	    events.perf_submit(ctx, &event, sizeof(struct event_t));

		if (walker->d_parent == walker->d_parent->d_parent)
			break;
		walker = walker->d_parent;
    }
	`

	gatherStr = `
	struct event_t event = {};
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task();
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.ppid = task->real_parent->tgid;
	`

	retStr = `
	event.retval = PT_REGS_RC(ctx);
	event.ret = ` + strconv.Itoa(eventRet) + `;
	events.perf_submit(ctx, &event, sizeof(event));
	return 0;
	`
)
