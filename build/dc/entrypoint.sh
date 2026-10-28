#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm BRIGHTWELL.LAB once (skipped on restart),
#   2. creates the low-privilege foothold user `s.adeyemi` and a decoy user `p.oduya`,
#   3. creates the service account `svc-moodle` and leaks its own password in the LDAP
#      `description` attribute (readable by any authenticated user),
#   4. builds the nested group chain  svc-moodle -> "IT-Staff" -> "Registry-Admins",
#   5. plants the flag in a share only "Registry-Admins" may read,
#   6. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
#
# Scenario: Brightwell University. The Moodle learning-management system syncs against AD under a
# dedicated service account (svc-moodle) whose password an administrator left in plain sight in
# its `description` attribute, where any authenticated user can read it.
set -euo pipefail

REALM="BRIGHTWELL.LAB"
DOMAIN="BRIGHTWELL"
BASE_DN="DC=brightwell,DC=lab"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Brightwell2024"
# Student's low-privilege foothold account (handed out in the lab message).
FOOTHOLD_USER="s.adeyemi"
FOOTHOLD_PASS="Student!2024"
# Decoy domain user (a lecturer; makes the directory feel real, leads nowhere).
DECOY_USER="p.oduya"
DECOY_PASS="Vt7q-Rm2k-Xp9!"
# Service account whose password is leaked in its LDAP description. Policy-compliant but
# recovered by simply reading the directory, not by guessing.
SVC_USER="svc-moodle"
SVC_PASS="M00dle-LDAP-2023!"
SVC_DESC="Moodle LMS directory sync account - do not disable. Initial password set to ${SVC_PASS}"
# Groups: the resource group that gates the registry share, and the nested group svc-moodle
# belongs to.
REGISTRY_GROUP="Registry-Admins"
NEST_GROUP="IT-Staff"
FACULTY_GROUP="Faculty"

PRIVATE_DIR="/var/lib/samba/private"
STAMP="${PRIVATE_DIR}/.isoloom-provisioned"

log() { echo "[dc] $*" >&2; }

if [ ! -f "${STAMP}" ]; then
  log "provisioning ${REALM} ..."
  rm -f /etc/samba/smb.conf
  # posix:eadb keeps NT ACLs in a tdb instead of security.* xattrs, so provisioning and the
  # file server work in an unprivileged container (no CAP_SYS_ADMIN); this option persists into
  # the generated smb.conf. (Relaxing "ldap server require strong auth" is done separately below,
  # because the provision --option for it does not get written to smb.conf.)
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=dc \
    --adminpass="${ADMIN_PASS}" \
    --option="posix:eadb=/var/lib/samba/eadb.tdb" >/dev/null

  # Kerberos client config and resolver point the DC at its own internal DNS.
  cp -f "${PRIVATE_DIR}/krb5.conf" /etc/krb5.conf

  # Publish the registry share that guards the flag.
  cat /opt/ldapenum/vault-share.conf >> /etc/samba/smb.conf

  touch "${STAMP}"
  log "provisioning done."
else
  log "already provisioned; reusing ${PRIVATE_DIR}."
fi

# Allow plain LDAP simple binds so the directory can be enumerated with ldapsearch / nxc ldap /
# BloodHound from the attack box. Samba's provision `--option` for this does NOT persist into the
# generated smb.conf, so we insert it into [global] ourselves (idempotent). Without it Samba
# answers a plain bind with "Strong(er) authentication required", and the lab is unsolvable over
# cleartext LDAP.
if ! grep -q 'ldap server require strong auth' /etc/samba/smb.conf 2>/dev/null; then
  log "relaxing LDAP strong-auth requirement (plain simple bind for enumeration)"
  sed -i '/^\[global\]/a\	ldap server require strong auth = no' /etc/samba/smb.conf
fi

# Resolver: the DC resolves its own realm through Samba's internal DNS.
printf 'nameserver 127.0.0.1\nsearch brightwell.lab\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.brightwell.lab' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.brightwell.lab dc\n' >> /etc/hosts 2>/dev/null || true

# Users are created offline against the local sam.ldb, so this works whether or not the samba
# process is already running.
if ! samba-tool user list 2>/dev/null | grep -qx "${FOOTHOLD_USER}"; then
  log "creating foothold user ${FOOTHOLD_USER}"
  samba-tool user create "${FOOTHOLD_USER}" "${FOOTHOLD_PASS}" >/dev/null
fi

if ! samba-tool user list 2>/dev/null | grep -qx "${DECOY_USER}"; then
  log "creating decoy user ${DECOY_USER}"
  samba-tool user create "${DECOY_USER}" "${DECOY_PASS}" \
    --given-name=Priya --surname=Oduya >/dev/null
fi

if ! samba-tool user list 2>/dev/null | grep -qx "${SVC_USER}"; then
  log "creating service account ${SVC_USER}"
  samba-tool user create "${SVC_USER}" "${SVC_PASS}" \
    --description="${SVC_DESC}" >/dev/null
fi

# Make absolutely sure the leaked password sits in `description` (idempotent: a restart that
# reused an existing account still ends up with the right value).
CUR_DESC="$(samba-tool user show "${SVC_USER}" --attributes=description 2>/dev/null \
            | awk -F': ' '/^description:/{print substr($0, index($0,": ")+2); exit}')"
if [ "${CUR_DESC}" != "${SVC_DESC}" ]; then
  log "setting ${SVC_USER} description (leaked password)"
  SVC_DN="$(samba-tool user show "${SVC_USER}" 2>/dev/null | awk -F': ' '/^dn:/{print $2; exit}')"
  if [ -n "${SVC_DN}" ]; then
    cat > /tmp/desc.ldif <<EOF
dn: ${SVC_DN}
changetype: modify
replace: description
description: ${SVC_DESC}
EOF
    ldbmodify -H "${PRIVATE_DIR}/sam.ldb" /tmp/desc.ldif >/dev/null 2>&1 || true
    rm -f /tmp/desc.ldif
  fi
fi

# Groups and the nested membership that forms the only path to the registry share:
#   svc-moodle  (member of)  "IT-Staff"  (member of)  "Registry-Admins"  -> registry share.
# s.adeyemi and p.oduya are in none of these, so neither can reach the flag directly.
for g in "${FACULTY_GROUP}" "${NEST_GROUP}" "${REGISTRY_GROUP}"; do
  if ! samba-tool group list 2>/dev/null | grep -qx "${g}"; then
    log "creating group ${g}"
    samba-tool group add "${g}" >/dev/null
  fi
done

add_member() { # group member -- idempotent
  local grp="$1" mem="$2"
  if ! samba-tool group listmembers "${grp}" 2>/dev/null | grep -qix "${mem}"; then
    log "adding ${mem} to '${grp}'"
    samba-tool group addmembers "${grp}" "${mem}" >/dev/null
  fi
}
add_member "${FACULTY_GROUP}"  "${DECOY_USER}"
add_member "${NEST_GROUP}"     "${SVC_USER}"
add_member "${REGISTRY_GROUP}" "${NEST_GROUP}"   # nested group membership

# Passwords never expire, so the lab behaves the same on day 1 and day 60.
for u in "${FOOTHOLD_USER}" "${DECOY_USER}" "${SVC_USER}"; do
  samba-tool user setexpiry "${u}" --noexpiry >/dev/null 2>&1 || true
done

# Plant the flag inside the registry share. CTF_FLAG_MAIN is delivered by the launcher at /ctf/flag
# (Isoloom's sensitive-input-as-file mechanism); fall back to a dev flag for a bare run.
mkdir -p /srv/registry
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/registry/flag.txt
else
  printf 'FLAG{dev-ldap-enum-brightwell-svc-moodle}\n' > /srv/registry/flag.txt
fi
chmod 0444 /srv/registry/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
