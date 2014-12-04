obj-m += eltsk.o

eltsk-y := elts.o hash.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod eltsk.ko

uninstall:
	rmmod eltsk.ko	
