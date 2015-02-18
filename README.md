# Postfix Policy Daemon 

Perl Postfix Policy daemon (see http://www.postfix.org/SMTPD_POLICY_README.html) which :

 * Performs DNS Blacklist scoring - you  can assign scores to each and threshold at which the mail is rejected.
 * Performs GeoIP scoring - if you don't like certain countries...
 * Performs SPF checking - does the client ip address have permission to send for the domain?
 * Performs RHSBL checks on the sender domain 


This code is loosely based on : 

 * http://bazaar.launchpad.net/~kitterman/postfix-policyd-spf-perl/trunk/files  (basic structure, SPF checks)
 * and https://github.com/palepurple/policyd-weight (black lists, geoip checks)

## License 

GPL v2

## What it does 

 * Check SMTP envelope headers for SPF confirmity. 
 * Check DNS Blacklists for the Client IP address (i.e. the IP sending mail to us)
 * Perform GeoIP scoring (client ip addr)
 * Check the sender's domain and see if it's in a RHS blacklist.


It doesn't (yet) do much with the helo (unless this is involved with the SPF check). 

 0. Ignore localhost or whitelisted entities such as known backup mx / relays.
 1. Check SPF stuff
 1. Perform DNS Blacklists checks on the client IP - each has varying score/weightings. Reject if total_score > threshold 
 3. Perform a GeoIP check, if e.g. it's from Nigeria, then perhaps we score it slightly higher than if it's from GB. 
 4. If the total score is > a threshold, again, reject it.
 5. Perform a RHSBL check, if e.g. it's listed under excommunicado.co.uk then score appropriately.
 6. If the total score is > a threshold, again, reject it.

The code currently implements simplisitc caching for :
 * Sender IP Addresses - if found to be blacklisted they'll remain blacklisted for about a day
 * Sender domain addresses - if found to be blacklisted they'll remain blacklisted for about a day


## Installation

 * Copy the src/policyd.pl script to somewhere useful.
 * Try and install Net::DNS::BL, if you can't use Client.pm bundled.
 * Install File::Cache or libfile-cache-perl [Debian] 
 * You'll probably need libnetaddr-ip-perl libmail-spf-perl libsys-hostname-long-perl libgeo-ip-perl libfile-cache-perl [Debian]
 * Edit /etc/postfix/master.cf (see below).
 * Edit /etc/postfix/main.cf (see below) to cause the policy daemon to be used.
 * Check syslog & /var/log/mail.log to see what's going on....

master.cf:

(choose something more descriptive than 'policyName').

```
 policyName  unix  -       n       n       -       15       spawn
    user=nobody argv=/path/to/policyd.pl  max_idle=30 max_use=50 daemon_timeout=50
```

(The max_use/max_idle/daemon_timeout aren't strictly necessary but seem sensible to ensure there are no potential issues with memory leaks).


main.cf:
```
 smtpd_recipient_restrictions =
   ... whatever ...
   check_policy_service unix:private/policyName
   ... whatever ...
```

## Configuration

Not yet very automated; read/edit src/policyd.pl as necessary.

## Tests 

```
cd tests
sh whatever.sh
```


## Other relevant links

 * Postfix documentation - http://www.postfix.org/SMTPD_POLICY_README.html
