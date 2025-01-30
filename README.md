dpdk-ddos-detect-dns
===============================================================
DNS server with ddos detect, ip blacklist filter，based on dpdk. It supports A and AAAA types.

### dpdk version and configuration of the project
本项目dpdk版本使用的是19.08.2，配置文件在conf中的map.conf配置，用于dns服务器记录的域名和ip，本项目支持A记录和AAAA记录

### dnsserver implementation and the method of ddos detect 
DNS基于udp在常规端口53上，采用流量窗口熵值检测ddos攻击异常，在流量从网卡流入时判断标记丢弃，不进一步进入dns解析逻辑处理，采用rte_hash进行ip blacklist进行请求频率限制，仅供学习使用。

### environment setup
```
# cd dpdk-xxx
# sudo ifconfig eth0 down
# ./usertools/dpdk-setup.sh
# 43 44 46 47 49
# cd x86_64-native-linuxapp-gcc/kmod/
# sudo insmod rte_kni.ko carrier=on
```

### compile and start program
```
# cd dpdk-ddos-detect-dns-master
# make 
# sudo ./build/dnsserver conf/map.conf
# sudo ifconfig vEth0 <any ip for dnsserver> up
```

### dns query and test
```
# dig @8.8.8.8 example.com
# dnsperf -d testfile -s <your dnsserver ip> -Q1000 -c1000
```

###
```
测试结果都位于test目录中
```

### traffic monitoring
```
# ./monitor.sh

```