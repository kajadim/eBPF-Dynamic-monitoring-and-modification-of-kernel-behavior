# eBPF-Dynamic-monitoring-and-modification-of-kernel-behavior

A real-time system observability tool using eBPF and the BCC (BPF Compiler Collection) framework. This project monitors critical kernel events by hooking into system calls using kprobes and kretprobes.

## Architecture

- ebpf-probe.c: The C backend containing BPF programs that run in kernel space for low-overhead data collection.
- ebpf-runner.py: The Python frontend that compiles the C code, loads it into the kernel, and formats the output for the user.
- test.py: A verification script designed to trigger specific kernel events (I/O operations, process forking, and network traffic) to validate the accuracy of the monitors.

## Quick start

- Environment Setup Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

- Execute the runner with administrative privileges (required for eBPF). Use grep to filter relevant events in real-time and save them to a log file:

```bash
sudo python3 ebpf-runner.py | grep --line-buffered -E "test|python3" > output.txt
```

- The monitor runs in a blocking state, continuously listening for kernel events. To capture data, you must run the test script in a separate terminal while the runner is active:

```bash
python3 test.py
```

## Results

The output.txt file acts as a window into the Linux kernel. It captures the low-level events triggered by the test.py script that would otherwise be invisible to the user.
