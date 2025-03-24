# LinuxKernelDevelopment
**Project Status: Ongoing**

This project is an exploration of the Linux kernel and its interaction with hardware, specifically developed for x86-64 and arm64 architectures. Initially created for use with my ARM-based Raspberry Pi 5 running Raspberry Pi OS, the current version has been designed for x64-based systems. Certain functionality related to GPIO pins and breadboard integration, originally intended for the ARM version with the Raspberry Pi, has been commented out in this version. The final iteration of the project will focus primarily on supporting the Raspberry Pi. 
# Features
* File hiding via syscall hooking
* Module Hiding via removal from the linked list
* Persistence via cronjob configuration files
* Privilege escalation via modifications to the sudoers file
* kill hooking to recieve commands from user

# Upcoming Features
* ARM support
* Version 2 will explore eBPF, which appears to be an interesting avenue for further investigation
* Pictures of functionality, bugs, and the breadboard
# Installation and Requirements
This project has been tested on the following configurations:
* Ubuntu 24.01 with kernel version 6.11 (x86-64)
* Raspberry Pi OS version 6.6 (ARM), based on Debian v12

Please note that backportability is not supported, and there are no plans to offer it in the future. If you are interested in testing this project and potentially causing a kernel segmentation fault or system instability, you are welcome to clone the repository and insert the module. For safety, it is strongly recommended to test this in a virtual machine.

## Installation Steps

> git clone https://github.com/TheodoreC13/LinuxKernelDevelopment/main/

cd into the folder and make

> cd ~/Github/LinuxKernelDevelopment/ && make

Insert the mod into your kernel

> sudo insmod breadboard.ko

You will need to unhide the module to remove it normally

> kill -63 999

> sudo rmmod breadboard

# Known Issues
x64  
> segmentation fault when running lsmod. This is specifically on getdents64. When I run the code for the module hiding alone I don't have this issue, nor do I have this issue when I only hook kill. 


arm 
> register_ftrace_function() faileds with error -22
# Contributions
This is a personal research project, and I am not accepting contributions at this time. However, constructive feedback and critique are always welcome.
# License
This project is licensed under the MIT License. Feel free to modify and distribute this code according to the terms of the license.
# References
https://xcellerator.github.io/posts/linux_rootkits_11/ 

https://github.com/h3xduck/TripleCross

https://github.com/ait-aecid/caraxes

https://github.com/m0nad/Diamorphine

https://github.com/f0rb1dd3n/Reptile

https://github.com/QuokkaLight/rkduck

https://github.com/croemheld/lkm-rootkit

https://github.com/ait-aecid/rootkit-detection-ebpf-time-trace

https://github.com/ilammy/ftrace-hook

https://github.com/reveng007/reveng_rtkit

https://www.youtube.com/watch?v=g6SKWT7sROQ

https://www.youtube.com/watch?v=EAjaXtjBWNY

https://web.archive.org/web/20140701183221/https://www.thc.org/papers/LKM_HACKING.html

https://web.archive.org/web/20160620231623/http://big-daddy.fr/repository/Documentation/Hacking/Security/Malware/Rootkits/writing-rootkit.txt
