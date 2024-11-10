# Simple linux auditd socket connection log parser.
Parses the audit.log file and reports on which user/executable opened a socket connection with resolved hostnames.

## Enable auditd rules for auditing socket connections.

Example:
```
auditctl -a always,exit -F arch=b64 -S connect -F key=network_connect
```

## Parse auditd logs for socket connections.
The parser prints out the user, executable and remote host, port or socket path opened.

```
# auditd-parser /var/log/audit/audit.log
"root" "/usr/sbin/NetworkManager" opened remote ubuntu-content-cache-3.ps5.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote blackcat.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote is-content-cache-2.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote is-content-cache-1.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote ubuntu-content-cache-1.ps5.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote ubuntu-content-cache-2.ps5.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote fracktail.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote ubuntu-content-cache-1.ps6.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote ubuntu-content-cache-2.ps6.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote ubuntu-content-cache-3.ps6.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote gladys.canonical.com port 80
"root" "/usr/sbin/NetworkManager" opened remote amyrose.canonical.com port 80
```