# Samba, acting as an Active Directory Domain Controller, in a single Linux container.
# It provisions the realm NORTH.SEVENKINGDOMS.LOCAL at first start (idempotent), plants a
# low-privilege foothold user (hodor), a service account (svc_backup) whose LDAP `description`
# leaks its own password, a nested group chain (IT Backup -> Vault Readers) that grants the
# only path to a `vault` share, and the flag inside that share. The enumeration tooling
# (ldap-utils, smbclient) ships in the image so the lab's check can prove the path from inside.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Preseed krb5 so its package install never prompts.
RUN set -eux; \
    echo "krb5-config krb5-config/default_realm string NORTH.SEVENKINGDOMS.LOCAL" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient ldb-tools \
        winbind libnss-winbind libpam-winbind \
        krb5-user krb5-config ldap-utils \
        dnsutils procps iproute2 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    # The AD DC runs as the single `samba` process, never the standalone smbd/nmbd/winbind
    # units, so make sure none of those can start on their own.
    rm -f /etc/samba/smb.conf

COPY vault-share.conf /opt/ldapenum/vault-share.conf
COPY check.sh         /opt/ldapenum/check.sh
COPY entrypoint.sh    /opt/ldapenum/entrypoint.sh
RUN chmod +x /opt/ldapenum/entrypoint.sh /opt/ldapenum/check.sh

# AD/Kerberos/LDAP surface.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp

CMD ["/opt/ldapenum/entrypoint.sh"]
