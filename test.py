import os
import socket
import time

with open("io_output.txt", "w") as f:
    f.write("This is the test entry for I/O performance.\n")
    f.flush()
    os.fsync(f.fileno())

pid = os.fork()
if pid == 0:
    os._exit(0)
else:
    os.wait()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"eBPF test", ("8.8.8.8", 80))
