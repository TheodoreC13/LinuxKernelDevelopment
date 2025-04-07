# LINUX KERNEL DEVELOPMENT PROJECT
This project is a linux kernel module (LKM) based rootkit proof of concept that I have created in order to better understand the differences between kernel space and user space as well as how an operating system functions with hardware.
## Features
* syscall intercepting
I specifically have intercepted 
* symbol tree exporting - using the kprobe solution that xcellerator uses
* file hiding
* module hiding
you can remove the module from the module list with
>
* persistence
I have a very basic persistence mechanism in place using 
> try_module_put(module) 
## Version 2 - eBPF based approach
While researching LKM based approaches I came across a better approach by using eBPF 
## Installation
Verify the kernel version is at least 5.7
> uanme -r
Clone repository
> git clone <link>
Enter the folder and make
> cd <folder> | make
load the modulle as root
> sudo insmod breadboard.ko
## Requirements
tested on Ubuntu v24.01 kernel version 6.11, and a raspberry pi 5 running RPOS kernel version 6.6, Debian v12
backportability is not supported nor should it work, this is specifically designed for linux kernels above version 5.5.7 due to kallsyms changes.
## Contributions
Due to this being a proof of concept and research project I am not interested in accepting contributions. Happily accepting critiques.
## License
GPL license
## References
