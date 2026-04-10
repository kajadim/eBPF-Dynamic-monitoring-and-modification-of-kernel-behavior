#!/usr/bin/env python3

from bcc import BPF
from pathlib import Path
import os

def process_clone_event(cpu, data, size):
    event = bpf["clone_events"].event(data)
    print(f"Process {event.comm.decode()} (PID: {event.pid}, PPID: {event.ppid}) called sys_clone")


def process_open_event(cpu, data, size):
    event = bpf["open_events"].event(data)
    print(
        f"[{event.timestamp / 1e9:.6f}] Process {event.comm.decode()} (PID: {event.pid}) opened file: {event.filename.decode()}")

def process_network_event(cpu, data, size):
    event = bpf["network_events"].event(data)
    print(f"[{event.comm.decode()}] Network packet sent!")

def process_io_event(cpu, data, size):
    event = bpf["io_events"].event(data)
    ms = event.duration_ns / 1e6
    print(f"[{event.comm.decode()}] I/O Write performed in {ms:.3f} ms")

my_pid = os.getpid()
bpf_source = Path('ebpf-probe.c').read_text()
bpf_source = bpf_source.replace("static u32 TARGET_PID = 0;", f"static u32 TARGET_PID = {my_pid};")
bpf = BPF(text=bpf_source)

bpf["clone_events"].open_perf_buffer(process_clone_event)
bpf["open_events"].open_perf_buffer(process_open_event)
bpf["network_events"].open_perf_buffer(process_network_event)
bpf["io_events"].open_perf_buffer(process_io_event)
print("Monitoring sys_clone and file open events... Press Ctrl+C to exit.")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break