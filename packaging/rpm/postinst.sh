#!/bin/sh
getent group  hypershunt >/dev/null || groupadd --system hypershunt
getent passwd hypershunt >/dev/null || \
    useradd --system --gid hypershunt --no-create-home \
            --shell /usr/sbin/nologin hypershunt
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Run: systemctl enable --now hypershunt"
echo "fail2ban jails installed but DISABLED; enable in /etc/fail2ban/jail.d/hypershunt.conf, then: systemctl reload fail2ban"
