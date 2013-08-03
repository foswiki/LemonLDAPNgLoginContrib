# Module of Foswiki Collaboration Platform, http://Foswiki.org/
#
# Copyright (C) 2013 Sven Dowideit, SvenDowideit@fosiki.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.

=pod

---+ package Foswiki::LoginManager::LemonLDAPNgLogin

The LemonLDAPNgLogin class uses LemonLDAP::NG's SSO to auto-login into Foswiki

=cut

package Foswiki::LoginManager::LemonLDAPNgLogin;

use strict;
use Assert;
use Foswiki::LoginManager::TemplateLogin;
use Foswiki::Func;

@Foswiki::LoginManager::LemonLDAPNgLogin::ISA =
  ('Foswiki::LoginManager::TemplateLogin');

sub new {
    my ( $class, $session ) = @_;

    my $this = bless( $class->SUPER::new($session), $class );
    $session->enterContext('can_login');

    return $this;
}

sub finish {
    my $this = shift;

    $this->SUPER::finish();
    return;
}

=pod

---++ ObjectMethod loadSession()


=cut

sub loadSession {
    my $this    = shift;
    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};

    #TODO: the cookiename is configurable
    my $ticket = $query->param('lemonldap');

    ASSERT( $this->isa('Foswiki::LoginManager::LemonLDAPNgLogin') ) if DEBUG;

    if ( $query->param('logout') && $Foswiki::cfg{CAS}{LogoutFromCAS} ) {

        $this->userLoggedIn( $Foswiki::cfg{DefaultUserLogin} );
        $foswiki->redirect( $this->logoutUrl(), 0 );
    }

# LoginManager::loadSession does a redirect on logout, so we have to deal with (CAS) logout before it.
    my $authUser = $this->SUPER::loadSession();
    my $uri      = Foswiki::Func::getUrlHost() . $query->uri();

    if ( 1 == 1 ) {    #}defined($ticket) ) {
        use Lemonldap::NG::Handler::CGI;
        my $cgi = Lemonldap::NG::Handler::CGI->new(
            {
                # Local storage used for sessions and configuration
                localStorage        => "Cache::FileCache",
                localStorageOptions => {
                    'namespace'          => 'lemonldap-ng',
                    'default_expires_in' => 600,
                    'cache_root'         => '/tmp',
                    'cache_depth'        => 5,
                },

                # How to get my configuration
                configStorage => {
                    type  => "SOAP",
                    proxy => "http://auth.fosiki.com/index.pl/config",
                },
                https => 0,

                # Optional
                #protection    => 'rule: $uid eq "admin"',
                # Or to use rules from manager
                protection => 'manager',

                # Or just to authenticate without managing authorization
                #protection    => 'authenticate',
            }
        );

        # Since authentication phase, you can use user attributes and macros
        my $login  = $cgi->user->{uid};
        my $name   = $cgi->user->{cn};
        my $groups = $cgi->user->{goups};
        my $email  = $cgi->user->{mail};

        print STDERR "==== $login: $name, $email, $groups\n";

        # Instead of using "$cgi->user->{groups} =~ /\badmin\b/", you can use
        #if( $cgi->group('admin') ) {
        # special html code for admins
        #}
        #else {
        # another HTML code
        #}
        if ($login) {
            $authUser = $login;
            $this->userLoggedIn($authUser);
        }
        else {

 # a bad ticket - so ignore
 # its a bit difficult if its a resubmit of an old ticket to the login script :/
        }
    }
    else {
        if (   defined( $query->param('sudo') )
            || defined( $query->param('logout') ) )
        {

            #sudo-ing, allow template auth
            $authUser = $Foswiki::cfg{DefaultUserLogin};
            $this->userLoggedIn($authUser);
        }
        else {
            if ( $foswiki->inContext('login') || $foswiki->inContext('logon') )
            {
                if ( !$this->forceAuthentication() ) {
                    my $full = $query->url( -full => 1 );
                    $uri =~ s/^$full//;
                    $uri = Foswiki::Func::getScriptUrl( undef, undef, 'view' )
                      . $uri;
                    $foswiki->redirect( $uri, 0 );
                }
            }
        }
    }

    return $authUser;
}

=begin TML

---++ ObjectMethod forceAuthentication () -> $boolean

method called when authentication is required - redirects to (...|view)auth
Triggered on auth fail

=cut

sub NOforceAuthentication {
    my $this    = shift;
    my $session = $this->{session};
    my $query   = $session->{request};

    if (   !$session->inContext('authenticated')
        && !defined( $query->param('lemonldap') ) )
    {
        $session->redirect( $this->loginUrl(), 0 );
        return 1;
    }
    return 0;
}

=begin TML

---++ ObjectMethod loginUrl () -> $loginUrl

over-ride the login url

=cut

sub NOloginUrl {
    my $this = shift;

    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};
    my $uri     = Foswiki::Func::getUrlHost() . $query->uri();

    #remove any urlparams, as they will be in the cachedQuery
    $uri =~ s/\?.*$//;
    return $this->{CAS}->getServerLoginURL(
        Foswiki::urlEncode( $uri . $foswiki->cacheQuery() ) );
}

=begin TML

---++ ObjectMethod logoutUrl () -> $loginUrl

can't over-ride the logout url yet, but will try to use it.

=cut

sub NOlogoutUrl {
    my $this = shift;

    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};
    my $uri     = Foswiki::Func::getUrlHost() . $query->uri();

    #remove any urlparams, as they will be in the cachedQuery
    $uri =~ s/\?.*$//;
    return $this->{CAS}->getServerLogoutURL(
        Foswiki::urlEncode( $uri . $foswiki->cacheQuery() ) );
}

1;
