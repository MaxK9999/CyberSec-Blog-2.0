---
title: HTB-Broken Shell
published: 2025-12-02
toc: true
draft: false
tags:
  - "Misc"
---

```
Scope:
94.237.49.88:39366
```

I was able to easily connect to the service using `nc -vn`:

![](attachments/e523e353afd1df681ed8c0bac9ffeedb.png)

Here I noticed that the following characters were whitelisted, and that they did not contain any *letters*.

```bash
[*] Allowed characters: ^[0-9${}/?"[:space:]:&>_=()]+$
```

This meant I'd need to think outside of the box with my enumeration, for example:

- Regular commands such as `ls -la` will not work.

![](attachments/f20b5c2f225b6299c639759b49eb549c.png)

Since I want to enumerate the current working directory I can use [this blog post](https://jrb.nz/posts/bash-tricks/) to find useful `bash` commands that don't involve letters.

![](attachments/89d80676a47e373000a90c58165c3175.png)

I tried the above but found the following error:

![](attachments/d803ca7ac6ecd7ae1a5312154210e99f.png)

If we try to execute the above command, the shell expands it to _every_ matching file (like `/bin/cp`, `/bin/ls`, `/bin/rm`) and tries to run the first one with the others as arguments. After some testing I found that the `/bin/ls` binary was in **7th** which meant I could use the following command to execute it: 

```bash
_(){ $7& } && _ /???/??
```

![](attachments/ff53e77d2f4661aef55468215cfac100.png)

Accordingly I found that the `/bin/cat` command was **3rd**, meaning I could execute it along with the `?` wildcard operator for the duration of the flag file:

```bash
_(){ $3 ???????????????????& } && _ /???/???
```

![](attachments/e5c561a6268ef43cebcc1db85ee2d39a.png)

![](attachments/7cf29cbdac8b1929043114f9ea4b8979.png)

---