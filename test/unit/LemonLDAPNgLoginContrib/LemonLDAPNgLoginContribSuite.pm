package LemonLDAPNgLoginContribSuite;

use Unit::TestSuite;
our @ISA = qw( Unit::TestSuite );

sub name { 'LemonLDAPNgLoginContribSuite' }

sub include_tests { qw(LemonLDAPNgLoginContribTests) }

1;
