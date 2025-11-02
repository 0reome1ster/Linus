obj-m += rootkit.o

rootkit-objs += main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	gcc hacker.c -o hacker

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm hacker