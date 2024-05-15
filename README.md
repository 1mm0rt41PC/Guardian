# The Guardian

`The Guadian` is a simple script that watch for unusual tcp/http/ssh activity and ban ip via routing. It's a fail2ban like with some integrated feature and simplified configuration. 
The script install a iptables rule to catch all trafic to closed ports. Then the script parse logs: `/var/log/messages` `/var/log/nginx/access.log`


# Docker
```bash
docker run --name guardian -d --restart=always -v /var/log:/var/log -v /etc/guardian/:/etc/guardian/:ro -v /sys:/sys -v /proc:/proc -v /dev:/dev --network=host --privileged -e WATCH_PORTS_TCP=auto -e WATCH_PORTS_UDP=auto -e INTERFACE=ens3 -e BAN_DURATION=`expr 60 '*' 30` -e BAN_INCREMENTATION=`expr 60 '*' 5` 1mm0rt41pc/guardian
```

# Install
```bash
# Install the script
root@1mmort41:~$ wget https://github.com/1mm0rt41PC/Guardian/raw/master/guardian.py -O /root/guardian.py

# Edit the configuration in the script:
root@1mmort41:~$ cat .env
# List of ports to be monitored.
# if WATCH_PORTS_TCP='auto' => WATCH_PORTS_TCP will be generated at with netstat/ss
# It's possible to invert the liste of ports by adding an extra ! before the list:
# WATCH_PORTS_TCP='!22,80,443' => banny any access to all ports except on ports 22,80,443
export WATCH_PORTS_TCP=auto
export WATCH_PORTS_UDP=auto
# Interface to watch
export INTERFACE=ens3
# Ban duration in seconde (default: 30 minutes)
export BAN_DURATION=`expr 60 '*' 30`
# Ban duration in case of recurrence in seconde. This time is added according to the following formula: {TG_BAN_LEN}+{Number of ban}*TG_BAN_INC
export BAN_INCREMENTATION=`expr 60 '*' 5`
root@1mmort41:~$ source .env
root@1mmort41:~$ python /root/guardian.py install

# Run The Guardian

root@1mmort41:~$ guardian run
NB instance: 1
root     30469  0.0  0.3  25120  7844 ?        Ss   22:31   0:00 /usr/bin/python /usr/local/bin/guardian daemon
[*] Dameon mode

# Check if the iptables rules are in place
root@1mmort41:~$ iptables -nvL
Chain INPUT (policy ACCEPT 380 packets, 26498 bytes)
 pkts bytes target     prot opt in     out     source               destination
 1020  103K ACCEPT     all  --  ens3   *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
    9   372 LOG        tcp  --  ens3   *       0.0.0.0/0            0.0.0.0/0            multiport dports  !22,25,53,80,443 LOG flags 0 level 4 prefix "[IPTABLES]"

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 1326 packets, 135K bytes)
 pkts bytes target     prot opt in     out     source               destination
```


# Usage
```
root@1mmort41:~$ guardian
[*]
[*] Usage:
[*]     status/st: show dropped/white-listed ip
[*]     unban <ip>: UnBan an ip
[*]     cleanup: UnBan all ip
[*]     run: run guardian into a new process
[*]     kill/stop: kill all guardian
[*]     install: install in the cron
[*]     log: show logs
[*]     test: Test RegExp
[*]     standalone/daemon: run in standalone or in daemon mode
```

## Debug The Guardian
Run the script in `standalone` mode in order to debug in live.
```bash
root@1mmort41:~$ guardian standalone
[2019/06/16 #24° 23:12:04] Init iptables
[2019/06/16 #24° 23:12:04] List of ports watched !25,53,80,443,686,5001,6690,8181
[2019/06/16 #24° 23:12:04] Disable logging martians packets
[2019/06/16 #24° 23:12:04] Loading ban timer for each IP...
[2019/06/16 #24° 23:50:50] Watch log /var/log/messages
[2019/06/16 #24° 23:50:50] Watch log /var/log/auth.log
[2019/06/16 #24° 23:50:50] Watch log /var/log/nginx/access.log
[2019/06/16 #24° 23:50:50] The Guardian is up and running
[2019/06/16 #24° 23:51:23] Ban IP 164.x.x.x with the reason access to port 8000
[2019/06/16 #24° 23:51:23] IP 164.x.x.x has been banned for 125 minutes
[2019/06/16 #24° 23:54:25] Ban IP 151.x.x.x with the reason access to port 3389
[2019/06/16 #24° 23:54:25] IP 151.x.x.x is white listed
[2019/06/16 #24° 23:57:34] Ban IP 90.x.x.x with the reason access to port 22
[2019/06/16 #24° 23:57:34] IP 90.x.x.x is connected via SSH. No ban for that IP !
```

## Get the status of The Guardian
```
root@1mmort41:~$ guardian status
[*] Instance
NB instance: 1
    root     30469  1.3  1.1  39056 23188 ?        Ss   22:31   0:00 /usr/bin/python /usr/local/bin/guardian daemon

[*] Actualy dropped

[*] Actualy BLACK listed

[*] Most viewed ports
    35132 count on port 3389
    34380 count on port 22
    22330 count on port 23
    04045 count on port 445
    03839 count on port 8080
    03230 count on port 81
    02207 count on port 8088
    01975 count on port 5555
    01849 count on port 2323
    01563 count on port 3306
    01182 count on port 8545
    01121 count on port 1433
    00935 count on port 3128
    00803 count on port 6379
    00710 count on port 21
    00703 count on port 5900
    00628 count on port 8888
    00627 count on port 8443
    00623 count on port 9000
    00550 count on port 5038
    00536 count on port 3390
    00529 count on port 139
    00524 count on port 27017
    00521 count on port 8081
    00488 count on port 7001
    00469 count on port 8000
    00463 count on port 2222
    00462 count on port 36003
    00461 count on port 50802
    00447 count on port 9001
[*] Most viewed ports this week
    00328 count on port 3389
    00319 count on port 22
    00196 count on port 23
    00027 count on port 8080
    00024 count on port 445
    00019 count on port 81
    00017 count on port 8545
    00017 count on port 5555
    00016 count on port 8088
    00012 count on port 50802
    00012 count on port 3306
    00011 count on port 1433
    00009 count on port 8089
    00009 count on port 3128
    00009 count on port 2323
    00007 count on port 5900
    00006 count on port 3380
    00006 count on port 139
    00005 count on port 8443
    00005 count on port 8081
    00005 count on port 60001
    00005 count on port 3388
    00005 count on port 21
    00005 count on port 1723
    00005 count on port 11211
    00004 count on port 8082
    00004 count on port 7001
    00004 count on port 6379
    00004 count on port 5038
    00004 count on port 3397
[*] Most viewed ports last week
    02448 count on port 22
    02407 count on port 3389
    01222 count on port 23
    00280 count on port 8088
    00199 count on port 445
    00192 count on port 8080
    00155 count on port 81
    00128 count on port 5555
    00093 count on port 2323
    00089 count on port 3306
    00081 count on port 8545
    00079 count on port 8291
    00075 count on port 1433
    00050 count on port 9000
    00050 count on port 3128
    00049 count on port 60001
    00047 count on port 139
    00046 count on port 8888
    00041 count on port 5900
    00040 count on port 21
    00039 count on port 6379
    00037 count on port 8443
    00035 count on port 36003
    00033 count on port 5060
    00032 count on port 8081
    00032 count on port 5038
    00032 count on port 1080
    00031 count on port 2222
    00030 count on port 50802
    00028 count on port 25565
[*] Evolution between this week and last week
    3389 (1)
    22 (-1)
    23 (-)
    8080 (2)
    445 (-)
    81 (1)
    8545 (4)
    5555 (-)
    8088 (-5)
    50802 (19)
    3306 (-1)
    1433 (1)
    8089 (38)
    3128 (1)
    2323 (-6)
    5900 (3)
    3380 (793)
    139 (-1)
    8443 (3)
    8081 (5)
    60001 (-5)
    3388 (49)
    21 (-3)
    1723 (9)
    11211 (11)
    8082 (357)
    7001 (19)
    6379 (-7)
    5038 (-3)
    3397 (NEW)
[*] Evolution between this week and all time logs
    3389 (-)
    22 (-)
    23 (-)
    8080 (1)
    445 (-1)
    81 (-)
    8545 (4)
    5555 (-)
    8088 (-2)
    50802 (19)
    3306 (-1)
    1433 (-)
    8089 (49)
    3128 (-1)
    2323 (-6)
    5900 (-)
    3380 (112)
    139 (4)
    8443 (-1)
    8081 (4)
    60001 (19)
    3388 (17)
    21 (-8)
    1723 (9)
    11211 (9)
    8082 (70)
    7001 (-2)
    6379 (-14)
    5038 (-9)
    3397 (38)

[*] Actualy white listed
    127.0.0.1

[*] List of ports watched:
    ! 25,53,80,443
```