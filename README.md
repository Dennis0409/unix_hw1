# Secured API Call
## API List
1. open
2. read
3. write
4. getaddrinfo
5. connect
6. system

## Config.txt
```
BEGIN open-blacklist
/etc/passwd
/etc/group
END open-blacklist

BEGIN read-blacklist
-----BEGIN CERTIFICATE-----
END read-blacklist

BEGIN connect-blacklist
www.nycu.edu.tw:443
google.com:80
END connect-blacklist

BEGIN getaddrinfo-blacklist
www.ym.edu.tw
www.nctu.edu.tw
google.com
END getaddrinfo-blacklist
```
## Example
1.```./launcher ./sandbox.so config.txt cat /etc/passwd```
```
[logger] open ("/etc/passwd",0,-130048) = -1
cat: /etc/passwd: Permission denied
```
2.```./launcher ./sandbox.so config.txt cat /etc/hosts```
```
[logger] open ("/etc/hosts",0,0xfffe0400) = 4
[logger] read (4,0x7ffc58253b30,131072) = 240
[logger] write (1,0x7ffc5829cef0,240) = 240
127.0.0.1	localhost
127.0.1.1	user1-D820MT-D820SF-BM3CE

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
[logger] read (4,0x7ffc58253b30,131072) = 0
```
3. ```./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem```
```
[logger] open ("/etc/ssl/certs/Amazon_Root_CA_1.pem",0,0xfffe0400) = 4
[logger] read (4,0x7ffd0fcb1cd0,131072) = -1
cat: /etc/ssl/certs/Amazon_Root_CA_1.pem: Input/output error
cat: /etc/ssl/certs/Amazon_Root_CA_1.pem: Bad file descriptor
```
4.```./launcher ./sandbox.so config.txt wget http://google.com -t 1```
```
--2024-08-03 12:05:55--  http://google.com/
Resolving google.com (google.com)... [logger] getaddrinfo (google.com,(null),0x7ffd5bc35870,0x7ffd5bc35838) = -2
failed: Name or service not known.
wget: unable to resolve host address ‘google.com’
```
5.```./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1```
```
--2024-08-03 12:07:40--  https://www.nycu.edu.tw/
Resolving www.nycu.edu.tw (www.nycu.edu.tw)... [logger] getaddrinfo (www.nycu.edu.tw,(null),0x7fff8bf54b10,0x7fff8bf54ad8) = 0
203.68.12.9, 203.68.12.10, 163.28.83.113, ...
Connecting to www.nycu.edu.tw (www.nycu.edu.tw)|203.68.12.9|:443... [logger] connect (4,203.68.12.9,16) = -1
failed: Connection refused.
Connecting to www.nycu.edu.tw (www.nycu.edu.tw)|203.68.12.10|:443... [logger] connect (4,203.68.12.10,16) = -1
failed: Connection refused.
Connecting to www.nycu.edu.tw (www.nycu.edu.tw)|163.28.83.113|:443... [logger] connect (4,163.28.83.113,16) = -1
failed: Connection refused.
Connecting to www.nycu.edu.tw (www.nycu.edu.tw)|163.28.83.114|:443... [logger] connect (4,163.28.83.114,16) = -1
failed: Connection refused.
```
6.```./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1```
```
[logger] getaddrinfo (www.google.com,(null),0x7ffca5dfcd80,0x7ffca5dfcd48) = 0
[logger] connect (4,0.0.0.0,28) = 0
[logger] write (4,0x7ffca5dfccf0,141) = 141
[logger] read (4,0x7ffca5db3900,511) = 511
[logger] read (4,0x7ffca5db3900,512) = 512
[logger] read (4,0x7ffca5db3900,33) = 33
[logger] read (4,0x7ffca5db3520,6) = 6
[logger] read (4,0x7ffca5db3580,8192) = 8192
[logger] read (4,0x7ffca5db3580,5463) = 2826
[logger] read (4,0x7ffca5db3580,2637) = 2637
[logger] read (4,0x7ffca5db3520,2) = 2
[logger] read (4,0x7ffca5db3520,5) = 5
[logger] read (4,0x7ffca5db3580,506) = 506
[logger] read (4,0x7ffca5db3520,2) = 2
[logger] read (4,0x7ffca5db3520,6) = 6
[logger] read (4,0x7ffca5db3580,6560) = 5298
[logger] read (4,0x7ffca5db3580,1262) = 1262
[logger] read (4,0x7ffca5db3520,2) = 2
[logger] read (4,0x7ffca5db3520,3) = 3
[logger] read (4,0x7ffca5db3520,2) = 2
```