	echo "cd  /root/atk/">>/etc/rc.local
	
	echo "insmod atk_eth0.ko">>/etc/rc.local
	echo "insmod atk_eth2.ko">>/etc/rc.local
	echo "insmod atk_eth1.ko">>/etc/rc.local
	echo "insmod atk_eth3.ko">>/etc/rc.local
	
	echo "./auto_atk_ip_eth0&">>/etc/rc.local
	echo "./auto_atk_ip_eth2&">>/etc/rc.local
	echo "./auto_atk_ip_eth1&">>/etc/rc.local
	echo "./auto_atk_ip_eth3&">>/etc/rc.local
	
	echo "./atk_svr_eth0&">>/etc/rc.local
	echo "./atk_svr_eth2&">>/etc/rc.local
	echo "./atk_svr_eth1&">>/etc/rc.local
	echo "./atk_svr_eth3&">>/etc/rc.local

	echo "/etc/init.d/iptables stop">>/etc/rc.local
	 