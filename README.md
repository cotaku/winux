winux
=====

This is a Linux kernel module that can be dynamically loaded into Linux kernel to support executing Win32 exe files directly.

Blog containing demo here (in Chinese): http://blog.atelier39.org/linux_driver/1077.html

How to build:

1. for winux: use make under Linux (tested in v2.6.x)

2. for kernel32.dll: use nmake under Windows

3. for test.exe: use make under Windows

How to run:

1. copy kernel32.dll to /usr/dlls/

2. insmod ./winux.ko

3. ./test.exe
