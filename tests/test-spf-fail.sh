echo "helo_name=mail.example.org
recipient=test@example.org
sender=test@example.org
client_address=94.68.181.45
request=smtpd_access_policy
" | perl -I ../src/ -w ../src/policyd.pl
