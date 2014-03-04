
echo "helo_name=mail.example.org
recipient=test@fish.net
sender=test@microsun.org
client_address=95.60.99.207
request=smtpd_access_policy
" | perl -I ../src/ -w ../src/policyd.pl
