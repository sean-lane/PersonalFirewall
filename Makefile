obj-m += FirewallKernelModule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) -I /usr/include modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
