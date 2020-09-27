# louis

`louis` is a simple tool using eBPF to automatically detect and respond to malicious behavior on a Linux system.

## Usage

```
Usage:
  louis [command]

Available Commands:
  help        Help about any command
  mitigate    Iterate through each known vulnerability and remediate
  monitor     Actively monitor for malicious action
  scan        Scan for malicious activity in common locations

Flags:
  -h, --help      help for louis
  -p, --passive   don't perform any intrusive action
  -v, --verbose   enable verbose output

Use "louis [command] --help" for more information about a command.
```

## Information

louis gathers information from the kernel through eBPF (with BCC). These sources are analyzed with information from categorized techniques and vulnerabilities.

```
                                                +------------+
                                                |            |
                                                | CLI Output |
                                                |            |
                                                +--------+---+
                                                         ^
                   +-------------------------------------|------+
                   |                                     |      |
+--------+         | +---------+    +----------+     +---+---+  |
|        |         | |         |    |          +---->+       |  |
|        |         | | Sources +--->+ Analysis |     | louis |  |
|        |   eBPF  | |         |    |          |     |       |  |
| Kernel +---------->+ Sockets |    +----------+     +--+----+  |
|        |         | | Users   |               ^        ^       |
|        |         | | Proc... |    +-------+  |        |       |
|        |         | |         |    |       |  |        v       |
+--------+         | +---------+    | Techs +<-+    +---+----+  |
                   |                |       |       | Output |  |
                   |                +-------+       +--------+  |
                   |                                            |
                   +--------------------------------------------+
```

> There is no kernelspace component, which means `louis` is more susceptible to resource exhaustion and any type of binary/execution manipulation. However, if that happens, you'll probably know about it.

## Screenshots & Examples

![Example of Louis Running](./docs/example.gif)

## Fun future activities

- Get absolute path for all openat syscalls (get task->fs->pwd.dentry->d_name.name for each dentry->d_parent)
- Macro/reduce code duplication in BPF code
- Sources
    - eBPF additions (other than itself)
    - sys_write
    - pam authentication

## Prior Art

- https://github.com/falcosecurity/falco well-made tool with a similar purpose and design. primarily c++. large backing by sysdig
- https://github.com/ION28/BLUESPAWN similar tool for Windows, made by very talented & welcoming devs
- https://github.com/D4stiny/PeaceMaker Windows heuristic monitoring tool made by a local cyber genius

## eBPF Resources and Libraries

- https://github.com/iovisor/gobpf
- https://github.com/iovisor/bcc
- http://www.brendangregg.com/Perf/bcc_tracing_tools.png
