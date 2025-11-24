---
title: 'HTB-Fries'
published: 2025-11-19
draft: true
toc: true
---

```
Scope:
10.10.11.96

Creds:
d.cooper@fries.htb
D4LE11maan!!
```

## CVE-2025-2945

![](attachments/f4dd6ca35ab14a4c9234eefac8e8fdce.png)

But the above PoC didnt work since it didn't work with kerberos auth. Instead I used the `metasploit` module it's based upon:

![](attachments/f0cc00fd9eaf09aa7482d23089d4802b.png)

Once I put down the following options I was able to run it successfully:

![](attachments/4822bbf77036217e545f5fb441a1b140.png)

![](attachments/b626e773652e041b3461a59dab72a001.png)

I started enumerating the directory:

![](attachments/110dba3b960c8c58d7952d95221195f5.png)

From here I enumerated the `env` variables where I found a cleartext password:

![](attachments/936310fdd0bff2c135b039ed8e541664.png)

```
Friesf00Ds2025!!
```

Next up I tried spraying this password against found users until I found one that matched:

![](attachments/299393f3bc59a8975ea1ecac4f063e31.png)

## SSH Access

Using these creds I logged in:

![](attachments/6dfde6b090b4da0e6a9c13265a18dc35.png)

### Mounting NFS Share

I used `ligolo` to port forward so I could access the `nfs` service:

![](attachments/1224f00d377121a256d8a167d231b625.png)

Once I had the port forward set up I created the drive I would mount the share 

```bash
sudo mkdir ./mount
sudo mount -t nfs -o ro,soft,timeo=10 240.0.0.1:/srv/web.fries.htb/certs ./mount
```

![](attachments/adfff3ee929b4e10db58ce52f017e6df.png)

![](attachments/9677bc00eb2d8a7ea756aecd68317c98.png)

I could still not access the mount though becaues I did not have the proper GUID:

![](attachments/31f8911107716837cf4d18c99e35fe01.png)

In order to get access I had to create a "dummy" account with this GUID.

```bash
sudo useradd tester
sudo nano /etc/passwd

# Add the following GUID
tester:x:1001:59605603::/home/tester:/bin/sh
```

![](attachments/d4194cb970e20016d24ed9a872c7435b.png)

Now we should be able to access the mounted share.

```bash
sudo -u tester cp -r mount /tmp/mount
sudo chown kali /tmp/mount
sudo chown kali /tmp/mount/*
sudo umount ./mount
```

![](attachments/06349388d2b3f9e6476f62b201f6fa7a.png)

![](attachments/0b97d002b7393b064780f0fe122d1fae.png)

# TODO FORGE ROOT cert.pem

```bash
docker context create remote-tls --docker "host=tcp://127.0.0.1:2376,\
ca=/home/svc/.docker/ca.pem,\     
cert=/home/svc/.docker/cert.pem,\     
key=/home/svc/.docker/key.pem"
```










---

**Finished**

[^Links]: [[Hack The Box]]