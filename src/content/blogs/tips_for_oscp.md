---
title: Tips for passing the OSCP exam
published: 2025-11-21
draft: false
toc: true
tags: ["OSCP", "OffSec", "Cyber", "pentesting"]
---

## 1. Prerequisites

So in order to even start *thinking* about the OSCP I honestly think that you should possess the following:

- Analytical thinking
- Motivation
- Discipline

While yes it is totally achievable to get the certification with no previous background just like I did, you still need to 
devote an absolute **boatload** of time.<br></br><br></br>
I was solving anywhere between 3-5 boxes a day during my preparation for the exam all while still working.
While there have been instances of people saying:
<br></br>
>*"Yeah I passed the OSCP exam with just 30 pwned CTF's"*

<br></br>
You really shouldn't compare yourselves to them because you have absolutely no idea what sort of previous knowledge they have.

The ONLY way to actually be able to pass the exam is putting in *hours and hours* of work and studying, and honestly, if you don't get
enjoyment out of solving CTF's then this really might not be for you.

Afterall, as I've already mentioned in the previous post, this is still just an ENTRY level certification


## 2. Is the course material enough?

After finishing all the course material I at first believed it was, but upon failing my first attempt I started having doubts.

Whether this was due to the course material being inadequate or that it was my fault for not being prepared enough, I had no answer for it.
However I **STRONGLY** advise to look for any and all outside material that you can get your hands on (afterall, this is basically what the course teaches you).

What I suggest:

1. Finish PEN-200 course material first (Please get the **LearnOne** package if you can)
2. Buy the **Penetration Tester** path on [HTB Academy](https://academy.hackthebox.com/path/preview/penetration-tester) and finish all the relevant modules (basically almost 100%)

All the while you're studying you should be rooting as many boxes as possible which brings me to my next point.

## 3. How many boxes are enough?

I see this question frequently asked on [Reddit](https://www.reddit.com/r/oscp/) and/or the official Discord channel. I understand that everyone is feeling pressured by the looming exam,
maybe even pressure from work, or maybe you only have 90 days course access so you're now stressing what to prioritize.

I still believe, and tell this to everyone, that *practice* is more important for **THIS SPECIFIC EXAM** than anything.
If you can root an intermediate box within 1 to 1.5 hours WITHOUT the use of writeups, you are *probably* safe.

If you bought the **LearnOne** package however, then you have some more time. 

In both cases, the more boxes the better. It is better to spend all your free time grinding boxes, than ending up having to pay the enormous price of a second attempt.

### 3.1 Prioritization

All in all I think you should do **AT LEAST** the following in this order:

#### Challenge Labs
1. Secura
2. Medtech
3. Relia
4. OSCP A 
5. OSCP B 
6. OSCP C 

#### Proving Grounds
- [TJNull List](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#)
- [LainKusanagi List](https://docs.google.com/spreadsheets/u/0/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/htmlview?pli=1#)

These 2 lists heavily overlap, but there are some differences. Focus on **Proving Grounds Practice** first, then do the HackTheBox ones if you have spare time.
Keep in mind that the HTB boxes really are way more difficult, an intermediate/hard level box from OffSec is often an **Easy** box on HTB.

Furthermore the HTB boxes are way less likely to contain easy credentials like `admin - admin` which is found almost in every OffSec box.

:::note
In my preparation for the second attempt I had finished ALL the PG boxes from Lain's list, all writeups are available on this site.
:::

## 4. Cheatsheets

Like most others I am against reading other's notes because you really don't learn anything from it. However I do think that some cheatsheets are extremely useful,
and you should definitely have these ready whenever you're doing a CTF. 

That said, here are some examples that I found incredibly useful both during my prep as well as during the exam:

- [Obsidian Canvas Cheatsheets](https://github.com/eMVee-NL/MindMap)
- [GTFObins](https://gtfobins.github.io/) (ABSOLUTE must, add to your browser bookmarks)
- [HackTricks](https://book.hacktricks.wiki/en/index.html) (saved my ass multiple times)
- [RevShells](https://www.revshells.com/) (use `busybox` for Linux and `Powershell #3 (Base64)` for Windows, works everytime)
- [Explanation of all potatoes](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
- [Online AD mindmap](https://mayfly277.github.io/assets/blog/pentest_ad_dark.svg) (I preferred the obsidian canvas one)
- [CrackStation](https://crackstation.net/) (quickly crack hashes, works about 50% of the time)

Don't just add these to your list but actually use them, that way you can get acquainted with them and speed up your workflow.





# TL;DR

:::tip
- Finish *ALL* the Proving Grounds Practice boxes from [this list](https://docs.google.com/spreadsheets/u/0/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/htmlview?pli=1#)
- Do all the provided Challenge Labs
- If you feel like the course material is inadequate, look for external material (such as HTB)
- Use Obsidian or any other note app to write down detailed cheatsheets
- Don't be afraid of looking at writeups, as long as you actually learn from them!
:::