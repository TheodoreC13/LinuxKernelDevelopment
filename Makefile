obj-m += breadboard.o
<<<<<<< HEAD

=======
#obj-m += showtest.o
>>>>>>> master

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
