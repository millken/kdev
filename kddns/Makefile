obj-m += kddns.o

kddns-y := hash.o main.o tld.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod kddns.ko

uninstall:
	rmmod kddns.ko	
