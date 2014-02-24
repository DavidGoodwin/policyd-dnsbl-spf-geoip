# Postfix Policy Daemon 

Perl Postfix Policy daemon (see http://www.postfix.org/SMTPD_POLICY_README.html) which :

 * Performs DNS Blacklist scoring - you  can assign scores to each and threshold at which the mail is rejected.
 * Performs GeoIP scoring - if you don't like certain countries...
 * Performs SPF checking - does the client ip address have permission to send for the domain?


This code is loosely based on : 

 * http://bazaar.launchpad.net/~kitterman/postfix-policyd-spf-perl/trunk/files  (basic structure, SPF checks)
 * and https://github.com/palepurple/policyd-weight (black lists, geoip checks)


## License 

GPL v2

## What it does 


 * Check SMTP envelope headers for SPF confirmity. 
 * Check DNS Blacklists for the Client IP address (i.e. the IP sending mail to us)
 * Perform GeoIP scoring (client ip addr)

It doesn't (yet) do anything with the helo, unlike policyd-weight, as this seems to trigger too many false positives.

 1. It has a list of DNS Blacklists each with varying score/weightings
 2. We undertake checks against the Blacklists
 3. Perform a GeoIP check, if e.g. it's from Nigeria, then perhaps we score it slightly higher than if it's from GB. 
 4. If the total score is > a threshold, again, reject it.

## Installation

 * Copy the src/policyd.pl script to somewhere useful.
 * Try and install Net::DNS::BL, if you can't use Client.pm bundled.
 * Edit /etc/postfix/master.cf (see below).
 * Edit /etc/postfix/main.cf (see below) to cause the policy daemon to be used.
 * Check syslog & /var/log/mail.log to see what's going on....

master.cf:

(choose something more descriptive than 'policyName').

```
 policyName  unix  -       n       n       -       0       spawn
    user=nobody argv=/path/to//policyd.pl
```

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

cd tests
sh whatever.sh

## Other relevant links

 * Postfix documentation - http://www.postfix.org/SMTPD_POLICY_README.html
