obj-m := atk_eth0.o atk_eth2.o atk_eth1.o atk_eth3.o

DIR  := /lib/modules/$(shell uname -r)/kernel/net/ipv4
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)


default: 
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	
	gcc auto_atk_ip_eth0.c -o auto_atk_ip_eth0
	gcc auto_atk_ip_eth2.c -o auto_atk_ip_eth2
	gcc auto_atk_ip_eth1.c -o auto_atk_ip_eth1
	gcc auto_atk_ip_eth3.c -o auto_atk_ip_eth3
	
	gcc atk_svr_eth0.c -o atk_svr_eth0
	gcc atk_svr_eth2.c -o atk_svr_eth2
	gcc atk_svr_eth1.c -o atk_svr_eth1
	gcc atk_svr_eth3.c -o atk_svr_eth3
	
	rm -rf *.c
	rm -rf *.o