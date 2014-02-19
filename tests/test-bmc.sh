echo "helo_name=mail.palepurple.co.uk
recipient=test@gmail.com
sender=dg@burton-mccall.co.uk
client_address=81.133.46.190
request=smtpd_access_policy
" | perl -I ../src -w ../src/policyd.pl
