---
title: HTB-Magical Palindrome
description: In Dumbledore's absence, Harry's memory fades, leaving crucial words lost. Delve into the arcane world, harness the power of JSON, and unveil the hidden spell to restore his recollection. Can you help harry yo find path to salvation?
published: 2025-11-29
toc: true
draft: false
tags: "Web"
---

```
Scope:
94.237.63.176:33769
```

# Source Code Review

I started off by downloading and extracting the pack:

![](attachments/a93a9b925a8f72de44f3ce7b587edb4e.png)

Inside I found the following contents:

![](attachments/7d76d7f3022832265c39a152b2dd34bd.png)

In order to view the source code I booted up `vscode` (this is not necessary but syntax highlighting is always a nice to have):

![](attachments/6b21ec57eaac8cba91177a79b6942803.png)

![](attachments/8691b0f82851efb057326543f0b561da.png)

The site itself just looked as follows:

![](attachments/3e7f7168a3c8a65d78bf77365ee04ae8.png)

Inside the `index.mjs` we see where the magic happens:

![](attachments/d1a4fd54567a5ba6b901d26d2bb2e5b5.png)

Checking the source code we can conclude the following:

- The server never verifies that `palindrome` is actually a string, so an attacker can provide an object with a forged `.length` property. 
- JavaScript’s numeric coercion makes `"1000"` behave like the number 1000, allowing the length check to pass. 
- The palindrome loop then only inspects keys `0` and `999`, so supplying matching values for those two keys makes the validator incorrectly accept the object as a valid palindrome.

# Exploitation

Since the string length has to be over `1000` I tried the following first:

![](attachments/a47e5d5f4fe4ec1cc0b412090d36193f.png)

This gave me the above response. 

I could bypass it using the following JSON string:

```js
{"palindrome":{"length":"1000","0":"a","999":"a"}}
```

![](attachments/d2385167b1e9792fe86fabed29a3413b.png)

![](attachments/c23fd3bae62c549359992a1842e402af.png)

---