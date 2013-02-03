winux
=====

This is a Linux kernel module that can be dynamically loaded into Linux kernel to support executing Win32 exe files directly.

Demos and compiled files here: http://www-users.cs.umn.edu/~zqi/projects/winux

How to build:

1. for winux: use make under Linux (tested in v2.6.x)

2. for kernel32.dll: use nmake under Windows

3. for test.exe: use make under Windows

How to run:

1. copy kernel32.dll to /usr/dlls/

2. #insmod ./winux.ko

3. #./test.exe

Author: Qi (from U of Minnesota)
Email: cotaku39 at gmail
