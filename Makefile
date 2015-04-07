obj-m += FirewallKernelModule.o

INC_PATH=/usr/include/linux
ccflags-y=-I$(INC_PATH)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load:
	# load module passing
	sudo insmod ./FirewallKernelModule.ko

unload:
	sudo rmmod FirewallKernelModule

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
