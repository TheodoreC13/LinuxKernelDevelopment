#obj-m += kprobetest.o
obj-m += breadboard.o
#obj-m += showtest.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
