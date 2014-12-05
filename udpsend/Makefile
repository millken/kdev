obj-m += udpsend.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod udpsend.ko

uninstall:
	rmmod udpsend.ko	
