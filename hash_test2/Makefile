obj-m += hashtest1.o

hashtest1-y := hash.o hashtest.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod hashtest1.ko

uninstall:
	rmmod hashtest1.ko	
