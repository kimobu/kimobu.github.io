---
title: Setting up a macOS Homelab
date: 2022-11-20
categories: []
tags: [homelab]
---

# External mail
## Postfix
https://orcacore.com/install-postfix-mail-server-ubuntu-22-04/

```
openssl req -newkey rsa:2048 -keyout /etc/ssl/private/mail-kvps.key.enc -x509 -days 365 -out mail-kvps.crt
openssl rsa -in /etc/ssl/private/mail-kvps.key.enc -out /etc/ssl/private/mail-kvps.key
```

Postfix main.cf
```
smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = mail.kvps.local, localhost.kvps.local, localhost
relayhost =
mynetworks = 127.0.0.0/8 10.10.41.0/24
inet_interfaces = all
recipient_delimiter = +
compatibility_level = 2
myorigin = /etc/mailname
mailbox_size_limit = 0
inet_protocols = ipv4
home_mailbox = Maildir/
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_local_domain =
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = noanonymous
broken_sasl_auth_clients = yes
smtpd_sasl_auth_enable = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtp_tls_note_starttls_offer = yes
smtpd_tls_key_file = /etc/ssl/private/mail-kvps.key
smtpd_tls_cert_file = /etc/ssl/certs/mail-kvps.crt
smtpd_tls_loglevel = 4
smtpd_tls_received_header = yes
myhostname = mail.kvps.local
smtpd_tls_auth_only = no
tls_random_source = dev:/dev/urandom
```

## Dovecot
https://ubuntu.com/server/docs/mail-dovecot

10-mail.conf
```
mail_location = maildir:~/Maildir
```
10-master.conf
```
unix_listener /var/spool/postfix/private/auth {
	mode = 0666
	user = postfix
	group = postfix
  }
```

## Roundcube
https://github.com/roundcube/roundcubemail/wiki/Installation

config.inc.php
```
$config['db_dsnw'] = 'mysql://USERNAME:PASSWORD@localhost/DATABASE';
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'localhost:25';
$config['support_url'] = 'http://localhost';
$config['des_key'] = 'YOURKEY';
$config['plugins'] = [];
$config['language'] = 'en_US';
$config['spellcheck_engine'] = 'enchant';
```

# Internal mail
## Exchange
Windows Server 2019 Standard
Add 64Gb drive. Install to D:\exchange

# DNS
named.conf.local
```
zone "kvps.local" {
	type master;
	file "/etc/bind/db.kvps.local";
};

zone "41.10.10.in-addr.arpa" {
	type master;
	file "/etc/bind/db.10";
};

zone "blue.local" {
	type master;
	file "/etc/bind/db.blue.local";
};
```

db.kvps.local
```
$TTL    604800
@       IN      SOA     kvps.local. root.kvps.local. (
							  4         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.kvps.local.
@       IN      A       10.10.41.103
ns      IN      A       10.10.41.103
@       IN      AAAA    ::1
@       IN      MX  1   mail.kvps.local.
mail    IN      A       10.10.41.102
```

db.blue.local
```
$TTL    604800
@       IN      SOA     blue.local. root.blue.local. (
							  2         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.blue.local.
@       IN      A       10.10.41.103
ns      IN      A       10.10.41.103
@       IN      AAAA    ::1
@       IN      MX  1   mail.blue.local.
mail    IN      A       10.10.41.100
```

db.10
```
$TTL    604800
@       IN      SOA     ns.kvps.local. root.ns.kvps.local. (
							  2         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.kvps.local.
@       IN      PTR     kvps.local.
mail    IN      A       10.10.41.102
ns      IN      A       10.10.41.103
@       IN      MX      102     mail.kvps.local.
103.10.10       IN      PTR     ns.kvps.local.


@       IN      SOA     ns.blue.local. root.ns.blue.local. (
							  2         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.blue.local.
@       IN      PTR     blue.local.
mail    IN      A       10.10.41.100
ns      IN      A       10.10.41.103
@       IN      MX      100     mail.blue.local.
103.10.10       IN      PTR     ns.blue.local.
```

MAIL FROM:<newsletter@contoso.com>
RCPT TO:<pam.beasley@blue.local>
DATA
Subject: Test from Contoso
This is a test message

# Security Onion
### Zeek
mkdir -p /opt/so/saltstack/local/salt/zeek/policy/custom
cd /tmp
git clone https://github.com/initconf/smtp-url-analysis.git
mv smtp-url-analysis/scripts/ /opt/so/saltstack/local/salt/zeek/policy/custom/
```
zeek:
  local:
    '@load':
      - custom/smtp_url/scripts
```
### Filebeat
./local/pillar/zeeklogs.sls
```
	- smtpurl_links
```
### Elasticsearch
```
/opt/so/saltstack/local/salt/elasticsearch/files/ingest/
 {
	"description" : "zeek.smtpurl_links",
	"processors" : [
	  { "remove":         { "field": ["host"],     "ignore_failure": true                                                                  } },
	  { "json":       { "field": "message",           "target_field": "message2",     "ignore_failure": true  } },
	  { "rename":     { "field": "message2.host",  "target_field": "smtp.url.host",       "ignore_missing": true  } },
	  { "rename":     { "field": "message2.url",  "target_field": "smtp.url.url",       "ignore_missing": true  } },
	  { "pipeline":       { "name": "zeek.common"                                                                                   } }
	]
  }
```