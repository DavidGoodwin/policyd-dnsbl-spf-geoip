#!/usr/bin/perl -w

# Basic policy daemon suitable for use under Postfix.
# See README.md in the root of this project.
# Author: Pale Purple Ltd <david-@-palepurple.co.uk>, 2014/02/xx.
# License: GPL v2 , see LICENSE.txt file.

# Notes:
# 1. You need/MUST edit the list of relay hosts (see relay_addresses constant below)
# 2. You probably want to edit the list of DNS Blacklists in use (see client_address_dnsbl subroutine below).

use NetAddr::IP;
use constant relay_addresses => map(
    NetAddr::IP->new($_),
    qw( 85.17.170.78 188.227.240.107 89.16.183.188 )
); # add addresses to qw (  ) above separated by spaces using CIDR notation.

use Getopt::Std;

use Cwd 'abs_path';
use File::Basename;
use lib dirname( abs_path $0 );

use version; our $VERSION = qv('1.00');

use strict;

# Net::DNSBL::Client (seems uninstallable through CPAN/Debian; hence manual inclusion)
require "Client.pm";

use IO::Handle;
use Sys::Syslog qw(:DEFAULT setlogsock);
use Mail::SPF;
use Sys::Hostname::Long 'hostname_long';
#use Net::DNSBL::Client;

use Data::Dumper;
use Geo::IP;

# If 550 someone via the DNSBL, then we cache it and quickly ignore them in the future.
use File::Cache;

# ----------------------------------------------------------
#                      configuration
# ----------------------------------------------------------

my $resolver = Net::DNS::Resolver->new(
    retrans         => 5,  # Net::DNS::Resolver default: 5
    retry           => 2,  # Net::DNS::Resolver default: 4
    # Makes for a total timeout for UDP queries of 5s * 2 = 10s.
);

# query_rr_type_all will query both type TXT and type SPF. This upstream
# default is changed due to there being essentially no type SPF deployment.
# query_rr_type_txt - TXT type RRs only.
# query_rr_type_all - TXT and  SPF type RRs
# query_rr_type_spf - SPF type RRs only.
my $spf_server = Mail::SPF::Server->new(
    dns_resolver    => $resolver,
    query_rr_types  => Mail::SPF::Server->query_rr_type_all,
    default_authority_explanation  => 'Please see http://www.openspf.net/Why?s=%{_scope};id=%{S};ip=%{C};r=%{R}'
);

# This will make the script far more verbose. Change this to 1.
# Otherwise we only log info & warning things and NOT debug.
# See my_syslog()
my $VERBOSE = 0;
my $DEBUG = 0;

# -d = Debug.
# -h = help
my %cmdline_options = ( 'h' => 0, 'd' => 0 );

getopts('hd', \%cmdline_options);

if($cmdline_options{'d'} eq '1') {
    $VERBOSE = 1;
    $DEBUG = 1;
}

if($cmdline_options{'h'} eq '1') {
    print " Usage : $0  -d => debug, -h => help \n";
    exit(0);
}

# List of functions/handlers to run for each policy request; 
# they're run in order. We need to exclude relay hosts or the local server 
# as they'll generally fail on SPF checks and it's a waste of resources.
my @HANDLERS = (
    { name => 'exempt_localhost', code => \&exempt_localhost },
    { name => 'exempt_relay', code => \&exempt_relay },
    { name => 'sender_policy_framework', code => \&sender_policy_framework },
    { name => 'client_address_dnsbl', code => \&client_address_dnsbl },
    { name => 'client_address_geoip', code => \&client_address_geoip },
    { name => 'client_address_rhsbl', code => \&client_address_rhsbl },
);


my $DEFAULT_RESPONSE = 'DUNNO';

# Syslogging options for verbose mode and for fatal errors.
# NOTE: comment out the $syslog_socktype line if syslogging does not
# work on your system.
my $syslog_socktype = 'unix'; # inet, unix, stream, console
my $syslog_facility = 'mail';
my $syslog_options  = 'pid';
# The name we appear in syslog under. 
my $syslog_ident    = 'postfix/policydpp';

use constant localhost_addresses => map(
    NetAddr::IP->new($_),
    qw(  127.0.0.0/8  ::ffff:127.0.0.0/104  ::1  )
);  # Does Postfix ever say "client_address=::ffff:<ipv4-address>"?

# Fully qualified hostname, if available, for use in authentication results
# headers now provided by the localhost and whitelist checks.
my  $host = hostname_long;

my %results_cache;  # by message instance

# ----------------------------------------------------------
#                      initialization
# ----------------------------------------------------------


my $file_cache = new File::Cache( { namespace => 'policyd', expires_in => 86400, username => 'policyd', filemode => 0600, cache_depth => 3 } );

#
# Log an error and abort.
#
sub fatal_exit {
    syslog(err     => "fatal_exit: @_");
    syslog(warning => "fatal_exit: @_");
    syslog(info    => "fatal_exit: @_");
    die("fatal: @_");
}

#
# Unbuffer standard output.
#
STDOUT->autoflush(1);

#
# This process runs as a daemon, so it can't log to a terminal. Use
# syslog so that people can actually see our messages.
#
setlogsock($syslog_socktype);
openlog($syslog_ident, $syslog_options, $syslog_facility);

# ----------------------------------------------------------
#                           main
# ----------------------------------------------------------

#
# Receive a bunch of attributes, evaluate the policy, send the result.
#
my %attr;

sub my_syslog {
    # Args: log type, message.
    my (@params) = @_; 
    #print Dumper(@params);
    if($DEBUG) {
        print $params[0] . " " . $params[1] . "\n";
    }

    if(!$VERBOSE && $params[0] eq 'debug') { 
        return;
    }
    syslog($params[0], $params[1]);
    #return syslog(@params);
}
while (<STDIN>) {
    chomp;
    
    if (/=/) {
        my ($key, $value) =split (/=/, $_, 2);
        $attr{$key} = $value;
        next;
    }
    elsif (length) {
        my_syslog('warning', sprintf("warning: ignoring garbage: %.100s", $_));
        next;
    }

    
    #if ($VERBOSE) {
    #    for (sort keys %attr) {
    #        my_syslog('debug', sprintf("Attribute: %s=%s", $_ || '<UNKNOWN>', $attr{$_} || '<UNKNOWN>'));
    #    }
    #};

    
    my $message_instance = $attr{instance};
    my $cache = defined($message_instance) ? $results_cache{$message_instance} ||= {} : {};
    
    my $action = $DEFAULT_RESPONSE;
   
    my $cumulative_score = 0;
    my $max_score = 6; # above this, we force 550 response
    my @pretty_text ;

    # Create Cache key based on sender ip addr?
    my $cache_key = $attr{client_address};

    if($file_cache->get($cache_key)) {
        STDOUT->print("action=550 DNS Blacklisted. REJECTED due to previous hits \n\n"); 
        exit(0);
    }

    foreach my $handler (@HANDLERS) {
        my $handler_name = $handler->{name};
        my $handler_code = $handler->{code};
        my %response = $handler_code->(attr => \%attr, cache => $cache);
        my_syslog('debug', "$handler_name => " . Dumper(\%response));

        # $response is now : ( score => $_->{hit}, action => 'DUNNO' , state => 'IN_' . $_->{country} );

        # skip this rule if score == 0 ?
        if($response{score} == 0 && $response{action} eq "DUNNO") {
            next;
        }

        $cumulative_score += $response{score};

        if($cumulative_score > $max_score) {
            my_syslog('debug', "Score now > $max_score ... 550'ing");
            $response{action} = "550";
        }
        # should perhaps nuke @pretty_text if the rule returned 0 ? (SPF data muted if it makes no difference.)
        push (@pretty_text, $response{state}) unless $response{state} eq '' or $response{state} =~ /Received-SPF: (neutral|none|softfail)/; # hacky.
        push (@pretty_text, 'SPF_SOFTFAIL') if $response{state} =~ /Received-SPF: softfail/; # hacky.
        my_syslog('debug', sprintf("handler %s: %s", $handler_name || '<UNKNOWN>', $response{state} || '<UNKNOWN>'));

        # Return back whatever is not DUNNO
        if (%response and $response{action} !~ /^(?:DUNNO|PREPEND)/i) {
            my_syslog('debug', sprintf("handler %s: is decisive.", $handler_name || '<UNKNOWN>'));
            $action = $response{action};
            last;
        }
    }
    
    my_syslog('info', sprintf("Policy action=%s, pretty text=%s", $action || '<UNKNOWN>', join(' ', @pretty_text)));
    my_syslog('debug', "action=$action " . join('; ', @pretty_text));
    
    STDOUT->print("action=$action " . join('; ', @pretty_text). "\n\n");

    %attr = ();
}

# ----------------------------------------------------------
#                handler: localhost exemption
# ----------------------------------------------------------

sub exempt_localhost {
    my %options = @_;
    my $attr = $options{attr};
    if ($attr->{client_address} ne '') {
        my $client_address = NetAddr::IP->new($attr->{client_address});
        return ( score => 0, action => "OK", state =>  "Authentication-Results: $host; none (SPF not checked for localhost)")
            if grep($_->contains($client_address), localhost_addresses);
    };
    return ( score => 0, action => 'DUNNO', state => '' ) ; # it's not localhost, so move on to another rule
}

# ----------------------------------------------------------
#                handler: relay exemption
# ----------------------------------------------------------

sub exempt_relay {
    my %options = @_;
    my $attr = $options{attr};
    if ($attr->{client_address} ne '') {
        my $client_address = NetAddr::IP->new($attr->{client_address});
        return ( score => 0, action => "OK", state => "Authentication-Results: $host; none (SPF not checked for whitelisted relay)" )
            if grep($_->contains($client_address), relay_addresses);
    };
    return ( score => 0, action => 'DUNNO', state => '') ; # it's not a whitelisted relay, so move on to another rule
}

# ----------------------------------------------------------
#                        handler: SPF
# ----------------------------------------------------------

sub sender_policy_framework {
    my %options = @_;
    my $attr    = $options{attr};
    my $cache   = $options{cache};
    
    # -------------------------------------------------------------------------
    # Always do HELO check first.  If no HELO policy, it's only one lookup.
    # This avoids the need to do any MAIL FROM processing for null sender.
    # -------------------------------------------------------------------------
    
    my $helo_result = $cache->{helo_result};
    
    if (not defined($helo_result)) {
        # No HELO result has been cached from earlier checks on this message.
        
        my $helo_request = eval {
            Mail::SPF::Request->new(
                scope           => 'helo',
                identity        => $attr->{helo_name},
                ip_address      => $attr->{client_address}
            );
        };
        
        if ($@) {
            # An unexpected error occurred during request creation,
            # probably due to invalid input data!
            my $errmsg = $@;
            $errmsg = $errmsg->text if UNIVERSAL::isa($@, 'Mail::SPF::Exception');
            my_syslog('info', 
                        sprintf("HELO check failed - Mail::SPF->new(%s, %s, %s) failed: %s", 
                            $attr->{client_address} || '<UNKNOWN>', 
                            $attr->{sender} || '<UNKNOWN>', 
                            $attr->{helo_name} || '<UNKNOWN>', 
                            $errmsg || '<UNKNOWN>'));
            return ( score => 0, action => 'DUNNO', state => 'HELO_SPF_FAIL' );
        }
        
        $helo_result = $cache->{helo_result} = $spf_server->process($helo_request);
    }
    
    my $helo_result_code    = $helo_result->code;  # 'pass', 'fail', etc.
    my $helo_local_exp      = nullchomp($helo_result->local_explanation);
    my $helo_authority_exp  = nullchomp($helo_result->authority_explanation)
        if $helo_result->is_code('fail');
    my $helo_spf_header     = $helo_result->received_spf_header;
    
    my_syslog('info', sprintf("SPF %s: HELO/EHLO: %s, IP Address: %s, Recipient: %s",
                $helo_result  || '<UNKNOWN>',
                $attr->{helo_name} || '<UNKNOWN>', 
                $attr->{client_address} || '<UNKNOWN>',
                $attr->{recipient} || '<UNKNOWN>'));
    
    # Reject on HELO fail.  Defer on HELO temperror if message would otherwise
    # be accepted.  Use the HELO result and return for null sender.
    if ($helo_result->is_code('fail')) {
        return ( score => 0, action => "550", state => $helo_authority_exp );
    }
    elsif ($helo_result->is_code('temperror')) {
        return ( score => 0, action => "DEFER_IF_PERMIT", state => "SPF-Result=$helo_local_exp" );
    }
    elsif ($attr->{sender} eq '') {
        return ( score => 0, action => "PREPEND", state => $helo_spf_header ) 
            unless $cache->{added_spf_header}++;
    }
    
    # -------------------------------------------------------------------------
    # Do MAIL FROM check (as HELO did not give a definitive result)
    # -------------------------------------------------------------------------
    
    my $mfrom_result = $cache->{mfrom_result};
    
    if (not defined($mfrom_result)) {
        # No MAIL FROM result has been cached from earlier checks on this message.
        
        my $mfrom_request = eval {
            Mail::SPF::Request->new(
                versions        => [1,2],
                scope           => 'mfrom',
                identity        => $attr->{sender},
                ip_address      => $attr->{client_address},
                helo_identity   => $attr->{helo_name}  # for %{h} macro expansion
            );
        };
        
        if ($@) {
            # An unexpected error occurred during request creation,
            # probably due to invalid input data!
            my $errmsg = $@;
            $errmsg = $errmsg->text if UNIVERSAL::isa($@, 'Mail::SPF::Exception');
            my_syslog('info', sprintf("Mail From (sender) check failed - Mail::SPF->new(%s, %s, %s) failed: %s",
                $attr->{client_address} || '<UNKNOWN>',
                $attr->{sender} || '<UNKNOWN>', $attr->{helo_name} || '<UNKNOWN>', $errmsg || '<UNKNOWN>'
            ));
            return ( score => 0, action => 'DUNNO' , state => 'SPF_INTERNAL_ERROR' );

        } 
        
        $mfrom_result = $cache->{mfrom_result} = $spf_server->process($mfrom_request);
    }
    
    my $mfrom_result_code   = $mfrom_result->code;  # 'pass', 'fail', etc.
    my $mfrom_local_exp     = nullchomp($mfrom_result->local_explanation);
    my $mfrom_authority_exp = nullchomp($mfrom_result->authority_explanation)
        if $mfrom_result->is_code('fail');
    my $mfrom_spf_header    = $mfrom_result->received_spf_header;
    
    my_syslog('debug', sprintf("SPF %s: Envelope-from: %s, IP Address: %s, Recipient: %s",
            $mfrom_result || '<UNKNOWN>',
            $attr->{sender} || '<UNKNOWN>', $attr->{client_address} || '<UNKNOWN>',
            $attr->{recipient} || '<UNKNOWN>'
        ));
    
    if ($mfrom_result->is_code('fail')) {
        return ( score => 0, action => "550", state => $mfrom_authority_exp );
    }
    elsif ($mfrom_result->is_code('temperror')) {
        return ( score => 0, action => "DEFER_IF_PERMIT", state => "SPF-Result=$mfrom_local_exp");
    }
    else {
        return ( score => 0, action => "PREPEND", state => $mfrom_spf_header )
            unless $cache->{added_spf_header}++;
    }
    
    return ( score => 0, action => 'DUNNO', state => '??' );
}

## GeoIP check on client address.
sub client_address_geoip {
    my %options = @_;
    my $attr    = $options{attr};
    my $cache   = $options{cache};
    # $attr{sender} $attr{recipient} $attr{client_address} $attr{helo_name}

    my @geoip_scores = (
        { country => 'GB', hit => -1 },
        { country => 'US', hit => -1 },
        { country => 'CN', hit => -1 },
        { country => 'RU', hit => 2 },
        { country => 'IN', hit => 2 },
    );

    our $geoip = Geo::IP->new(GEOIP_STANDARD);
    my $country = $geoip->country_code_by_addr($attr{client_address});
    if(!defined($country))
    {
        return ( score => 0, action => 'DUNNO', state => '' );
    }

    foreach (@geoip_scores) 
    {
        if($country eq $_->{country}) 
        {
            return ( score => $_->{hit}, action => 'DUNNO' , state => 'IN_' . $_->{country} );
        }
    }
    return ( score => 0, action => 'DUNNO', state => '' );
}

sub client_address_dnsbl {
    my %options = @_;
    my $attr    = $options{attr};
    my $cache   = $options{cache};
    # $attr{sender} $attr{recipient} $attr{client_address} $attr{helo_name}

    my @dns_bls = [
        { domain => 'zen.spamhaus.org',     userdata => { hit => 6.25, miss => 0, logname => 'ZEN_SPAMHAUS' 	}, type => 'normal' },
        #{ domain => 'sbl-xbl.spamhaus.org', userdata => { hit => 6.25, miss => 0, logname => 'SBL_XBL_SPAMHAUS' }, type => 'normal' },
        { domain => 'truncate.gbudb.net',   userdata => { hit => 3.0,  miss => 0, logname => 'TRUNCATE_GBUDB'   }, type => 'normal' },
        { domain => 'bl.spamcop.net',       userdata => { hit => 3.25, miss => 0, logname => 'SPAMCOP' 		}, type => 'normal' },
        { domain => 'dnsbl.sorbs.net', 	    userdata => { hit => 3.25, miss => 0, logname => 'SORBS' 		}, type => 'normal' },
        { domain => 'ix.dnsbl.manitu.net',  userdata => { hit => 3.25, miss => 0, logname => 'IX_MANITU' 	}, type => 'normal' },
        { domain => 'tor.ahnl.org', 	    userdata => { hit => 3.25, miss => 0, logname => 'AHNL_TOR' 	}, type => 'normal' },
    ];

    my $bl_client = Net::DNSBL::Client->new({timeout => 1, resolver => $resolver});
    my $client_address = $attr{client_address};

    my $ok = $bl_client->query_ip($client_address, @dns_bls, {return_all => 1});

    my $answers = $bl_client->get_answers();
    my $return = '';
    my $score = 0;
    my $dnsbl_threshold = 6.00;
    my $hit_count = 0;
    foreach my $answer (@$answers) {
        my $logname = $answer->{userdata}{logname};
        if($answer->{hit} == 1) {
            $hit_count += 1;
            $return .= " IN_" . $logname;
            $score += $answer->{userdata}{hit};
            my_syslog('debug', "Hit in $answer->{domain} for $client_address $logname");
        }
        else {
            $score += $answer->{userdata}{miss};
        }
    }

    # return ( score => $_->{hit}, action => 'DUNNO' , state => 'Textual Desc Of State IN_' . $_->{country} );

    # should we return DUNNO if there's some sort of error condition?
    my $from = $attr{sender};
    my $to = $attr{recipient};
    my $cache_key = $attr{client_address};

    if($score >= $dnsbl_threshold) {
        my_syslog('info', "550 DNS Blacklist hit ($score vs $dnsbl_threshold) for $from => $to; $return");

        # Cache the IP as evil.
        $file_cache->set($cache_key, 1);
        return ( score => $score, action => "550", state => "DNSBL Hit(s). Your MTA IP address ($client_address) is blacklisted. Contact your IT support/server administrator. $return");
    }

    if($hit_count == 0) {
        my_syslog('debug', "$DEFAULT_RESPONSE - No DNS Blacklist hits for $client_address, $from => $to");
        return ( score => 0, action => $DEFAULT_RESPONSE, state => 'DNSBL_FREE');
    }
    return ( score => $score, action => 'PREPEND', state => $return );
}


sub client_address_rhsbl {
    # An observant reader would notice there's a big duplication between this function and 
    # client_address_dnsbl with only about 4 things changing:
    # 1. The Net::DNSBL::Client call (query_domain)
    # 2. The return value(s) referencing RHSBL
    # 3. The cache key(s)
    # 4. The blacklist(s) to check.
    # Patches welcome.

    my %options = @_;
    my $attr    = $options{attr};
    # $attr{sender} $attr{recipient} $attr{client_address} $attr{helo_name}
    # take $attr{sender} and chop off the stuff before and including the @.
    if ( $attr{sender} eq "" || $attr{sender} !~ /@/ ) {
        my_syslog('debug', 'attr{sender} empty; cannot process');
        return ( score => 0, action => "DUNNO", state => "No sender address present, can't perform RHSBL check(s)" );
    }

    my ($crap,$sender_domain) = split('@', $attr{sender}, 2);

    my $cache_key = "rhsbl" . $sender_domain;

    if($file_cache->get($cache_key)) {
        return ( score => 10, action => "550", state => "RHSBL Hits (cached) (IN_EXCOMMUNICADO)"); # lazy hack until we cache things properly, given there's only one BL atm
    }
    my @sender_domain_blacklists = [
        { domain => 'excommunicado.co.uk',     userdata => { hit => 6.1, miss => 0, logname => 'EXCOMMUNICADO'   }, type => 'normal' },
    ];

    my $bl_client = Net::DNSBL::Client->new({timeout => 1, resolver => $resolver});
    my $ok = $bl_client->query_domain($sender_domain, @sender_domain_blacklists, {return_all => 1});
    my $answers = $bl_client->get_answers();
    my $return = '';
    my $score = 0;
    my $threshold = 6.00;
    my $hit_count = 0;
    #print Dumper(@$answers);

    foreach my $answer (@$answers) {
        my $logname = $answer->{userdata}{logname};
        if($answer->{hit} == 1) {
            $hit_count += 1;
            $return .= " IN_" . $logname;
            $score += $answer->{userdata}{hit};
            my_syslog('debug', "Hit in $answer->{domain} for $sender_domain $logname");
        }
        else {
            $score += $answer->{userdata}{miss};
        }
    }

    # return ( score => $_->{hit}, action => 'DUNNO' , state => 'Textual Desc Of State IN_' . $_->{country} );

    # should we return DUNNO if there's some sort of error condition?
    my $from = $attr{sender};
    my $to = $attr{recipient};

    if($score >= $threshold) {
        my_syslog('info', "550 RHBL Blacklist hit ($score vs $threshold) for $sender_domain / $from => $to; $return");

        # Cache the IP as evil.
        $file_cache->set($cache_key, 1);
        return ( score => $score, action => "550", state => "RHSBL Hit(s). Your sender domain ($sender_domain) is blacklisted. Contact your IT support/server administrator. $return");
    }

    if($hit_count == 0) {
        my_syslog('debug', "$DEFAULT_RESPONSE - No RHBL/DNS Blacklist hits for $sender_domain, $from => $to");
        return ( score => 0, action => $DEFAULT_RESPONSE, state => 'RHDNSBL_FREE');
    }
    return ( score => $score, action => 'PREPEND', state => $return );
}

# ----------------------------------------------------------
#                   utility, string cleaning
# ----------------------------------------------------------

sub nullchomp {
    my $value = shift;

    # Remove one or more null characters from the
    # end of the input.
    $value =~ s/\0+$//;
    return $value;
}

