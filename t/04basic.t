use Test::More tests => 12;

use_ok('Authen::Simple::Passwd');

ok( my $passwd = Authen::Simple::Passwd->new( passwd => 't/etc/passwd' ) );
ok(   $passwd->authenticate( 'apr1',  'apr1'  ), 'Successfully authenticated using $apr1' );
ok(   $passwd->authenticate( 'crypt', 'crypt' ), 'Successfully authenticated using crypt() with Traditional DES' );
ok(   $passwd->authenticate( 'md5',   'md5'   ), 'Successfully authenticated using $1$' );
ok(   $passwd->authenticate( 'plain', 'plain' ), 'Successfully authenticated using plain' );
ok(   $passwd->authenticate( 'sha',   'sha'   ), 'Successfully authenticated using {SHA}' );
ok( ! $passwd->authenticate( '-',     '-'     ), 'Usernames with hyphens is not allowed' );

ok( $passwd = Authen::Simple::Passwd->new( passwd => 't/etc/passwd', allow => [ 'md5', 'sha' ] ) );
ok( ! $passwd->authenticate( 'crypt', 'crypt' ), 'Crypt is not allowed' );
ok( ! $passwd->authenticate( 'plain', 'plain' ), 'Plain is not allowed' );
ok(   $passwd->authenticate( 'md5',   'md5'   ), 'Successfully authenticated using md5' );
