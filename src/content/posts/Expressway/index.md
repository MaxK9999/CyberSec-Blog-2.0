---
title: 'HTB-Expressway'
published: 2025-09-21
draft: false
toc: true
tags: ['ike', 'isakmp', 'CVE-2025-32463']
---

---

```
Scope:
10.10.11.87
```

# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- expressway.htb -T5 --min-rate=5000 -vvvv -Pn 

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only one port showed up so I decided to run a `UDP` scan as well.

```bash
sudo nmap -sV -sC -sU -p- expressway.htb -T5 --min-rate=5000 -vvvv -Pn

Discovered open port 500/udp on 10.10.11.87
```

Since the `500` port showed up I reran the scan focussing on this port.

```bash
sudo nmap -sV -sC -sU -p500 expressway.htb -T5 --min-rate=5000 -vvvv -Pn

PORT    STATE SERVICE REASON              VERSION
500/udp open  isakmp? udp-response ttl 63
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
```


## 500/UDP - ISAKMP

Using [this resource](https://book.hacktricks.wiki/en/network-services-pentesting/ipsec-ike-vpn-pentesting.html) I was able to learn more about this service.

![](attachments/4afabfc20253e23a93ea451a27a00e81.png)

Reading further down:

![](attachments/709f9083d8b04b515346850ee3d18570.png)

Let's get to it:

```bash
ike-scan -M --showbackoff expressway.htb
```

![](attachments/20fab7cb11951e67c3ad9cdd713c58e8.png)

### IKE Xauth

Since we're dealing with `Xauth` here we'll have to follow along with this part:

Using the `-A` aggressive mode we can acquire hashes and identities in cleartext:

![](attachments/cffb2e49910127611adc9241bb1bf087.png)

As well as the `psk` hashes:

![](attachments/01982ad0637bf97c769f9cfaf8bd4dc2.png)

### Hash cracking

I can find the correct hash format as follows:

![](attachments/121c31d665bd4d728f6d1fd5924ca701.png)

The `ike-scan` previously told us we're dealing with a `SHA1` hash:

![](attachments/1717b4f04e0e5ebddc5ddd1317065ce4.png)

Let's get to cracking.

![](attachments/e5afb103512fa8146b98c8974b5996ec.png)

![](attachments/9e99f479b65164ca527963acd5522faa.png)

```
ike@expressway.htb
freakingrockstarontheroad
```

# Foothold
## SSH as ike

We can use these creds to login via `ssh`:

![](attachments/94e62550e748427435d61698532d80d0.png)

Here we can instantly pick up `user.txt`.

# Privilege Escalation
## Enumeration

I noticed this user was part of the *proxy* group:

![](attachments/3cc5ee7d06d6ad516eb078fe90f34405.png)

We weren't able to run `sudo` either:

![](attachments/79856e9bd63354444b298a6fa6b2fa16.png)

For automated enum I ran `linpeas`:

![](attachments/517b147f4afead593a7351cba1b678ee.png)

![](attachments/2dc347380df887739563aad776cc9174.png)

From my memory I had previously found an exploit that could easily give us *root* by exploiting this `sudo` version:

![](attachments/fa6be969051293c5cfe9dd7cedf0fd95.png)

Let's try it out:

![](attachments/4b4b65bb63ec2ab5e7535ac987dcd9d9.png)

EZ PZ *root*.

![](attachments/05e8ae1f4fcbd04c9eb8219858ab8db9.png)

---