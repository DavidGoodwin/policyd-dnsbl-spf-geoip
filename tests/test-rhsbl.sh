
echo "helo_name=mail.example.org
recipient=test@fish.net
sender=returns@nameriver.net
client_address=89.16.169.141
request=smtpd_access_policy
" | perl -w ../src/policyd.pl
