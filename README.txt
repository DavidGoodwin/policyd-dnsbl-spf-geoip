= Postfix Policy Daemon =


Loosely based on http://bazaar.launchpad.net/~kitterman/postfix-policyd-spf-perl/trunk/files and https://github.com/palepurple/policyd-weight

License: GPL v2.

= What it does =

Check SMTP envelope headers [helo/smtp from/smtp to/client ip addr] for :

 * SPF  (to/from/client ip addr)
 * DNS Blacklists (client ip addr)
 * GeoIP scoring (client ip addr)

It doesn't yet do anything with the helo, unlike policyd-weight, as this seems to trigger too many false positives.

Ideally :

 1. It has a list of DNS Blacklists each with varying score/weightings
 2. We undertake checks against the Blacklists
 3. Perform a GeoIP check, if e.g. it's from Nigeria, then perhaps we score it slightly higher than if it's from GB. 
 4. If the total score is > a threshold, again, reject it.

= TODO =

Perhaps stop individual functions from deciding whether it's a DUNNO/PREPEND/550 etc and just do this globally based on total score.

= Tests =

cd tests
sh whatever.sh

= Other relevant links =

 * Postfix documentation - http://www.postfix.org/SMTPD_POLICY_README.html
