package Authen::Simple::Passwd;

use strict;
use warnings;
use bytes;
use base 'Authen::Simple::Adapter';

use Config           qw[];
use Crypt::PasswdMD5 qw[];
use Digest::SHA1     qw[];
use Digest::MD5      qw[];
use Fcntl            qw[:flock];
use IO::File         qw[O_RDONLY];
use Params::Validate qw[];

our $VERSION = 0.3;

__PACKAGE__->options({
    passwd => {
        type      => Params::Validate::SCALAR,
        optional  => 0
    },
    flock => {
        type      => Params::Validate::SCALAR,
        default   => ( $Config::Config{d_flock} ) ? 1 : 0,
        optional  => 1
    },
    allow => {
        type      => Params::Validate::ARRAYREF,
        default   => [ qw( apr1 crypt md5 plain sha ) ],
        optional  => 1,
        callbacks => {
            'valid option' => sub {

                foreach ( @{ $_[0] } ) {
                    return 0 unless $_ =~ /^apr1|crypt|md5|plain|sha$/;
                }

                return 1;
            }
        }
    }
});

sub check {
    my ( $self, $username, $password ) = @_;

    if ( $username =~ /^-/ ) {

        $self->log->debug( qq/User '$username' begins with a hyphen which is not allowed./ )
          if $self->log;

        return 0;
    }

    my $passwd = $self->passwd;

    unless ( -e $passwd) {

        $self->log->error( qq/passwd file '$passwd' does not exist./ )
          if $self->log;

        return 0;
    }

    unless ( -f _ ) {

        $self->log->error( qq/passwd file '$passwd' is not a file./ )
          if $self->log;

        return 0;
    }

    unless ( -r _ ) {

        $self->log->error( qq/passwd file '$passwd' is not readable by effective uid '$>'./ )
          if $self->log;

        return 0;
    }

    my $fh;

    unless ( $fh = IO::File->new( $passwd, O_RDONLY ) ) {

        $self->log->error( qq/Failed to open passwd '$passwd'. Reason: '$!'/ )
          if $self->log;

        return 0;
    }

    unless ( !$self->flock || flock( $fh, LOCK_SH ) ) {

        $self->log->error( qq/Failed to obtain a shared lock on '$passwd'. Reason: '$!'/ )
          if $self->log;

        return 0;
    }

    my $encrypted;

    while ( defined( $_ = $fh->getline ) ) {

        next if /^#/;
        next if /^\s+/;

        chop;

        my (@credentials) = split( /:/, $_, 3 );

        if ( $credentials[0] eq $username ) {

            $encrypted = $credentials[1];

            $self->log->debug( qq/Found user '$username' in passwd '$passwd'./ )
              if $self->log;

            last;
        }
    }

    unless ( $fh->close ) {

        $self->log->warn( qq/Failed to close passwd '$passwd'. Reason: '$!'/ )
          if $self->log;
    }

    unless ( defined $encrypted ) {

        $self->log->debug( qq/User '$username' was not found in '$passwd'./ )
          if $self->log;

        return 0;
    }

    my $match = 0;
    my %allow = map { $_ => 1 } @{ $self->allow };

    if ( !$match && $allow{apr1} && $encrypted =~ /^\$apr1\$/ ) {
        $match++ if Crypt::PasswdMD5::apache_md5_crypt( $password, $encrypted ) eq $encrypted;
    }

    if ( !$match && $allow{md5} && $encrypted =~ /^\$1\$/ ) {
        $match++ if Crypt::PasswdMD5::unix_md5_crypt( $password, $encrypted ) eq $encrypted;
    }

    if ( !$match && $allow{sha} && $encrypted =~ /^\{SHA\}/ ) {
        $match++ if sprintf( '{SHA}%s=', Digest::SHA1::sha1_base64($password) ) eq $encrypted;
    }

    if ( !$match && $allow{crypt} ) {
        $match++ if crypt( $password, $encrypted ) eq $encrypted;
    }

    if ( !$match && $allow{plain} ) {
        $match++ if $password eq $encrypted;
    }

    unless ( $match ) {

        $self->log->debug( qq/Failed to authenticate user '$username'. Reason: 'Invalid credentials'/ )
          if $self->log;

        return 0;
    }

    $self->log->debug( qq/Successfully authenticated user '$username'./ )
      if $self->log;

    return 1;
}

1;

__END__

=head1 NAME

Authen::Simple::Passwd - Simple Passwd authentication

=head1 SYNOPSIS

    use Authen::Simple::Passwd;
    
    my $passwd = Authen::Simple::Passwd->new( 
        passwd => '/etc/passwd'
    );
    
    if ( $passwd->authenticate( $username, $password ) ) {
        # successfull authentication
    }
    
    # or as a mod_perl Authen handler
    
    PerlModule Authen::Simple::Apache
    PerlModule Authen::Simple::Passwd

    PerlSetVar AuthenSimplePasswd_passwd "/etc/passwd"

    <Location /protected>
      PerlAuthenHandler Authen::Simple::Passwd
      AuthType          Basic
      AuthName          "Protected Area"
      Require           valid-user
    </Location>    

=head1 DESCRIPTION

Authenticate against a passwd file.

=head1 METHODS

=over 4

=item * new

This method takes a hash of parameters.  The following options are
valid:

=over 8

=item * passwd

Path to passwd file to authenticate against. Any standard passwd file that 
has records seperated with newline and fields seperated by C<:> is supported.
First field is expected to be username and second field, plain or encrypted 
password. Required.

    passwd => '/etc/passwd'
    passwd => '/var/www/.htpasswd'
    
=item * flock

A boolean to enable or disable the usage of C<flock()>. Defaults to C<d_flock> in L<Config>.

    flock => 0
    
=item * allow

An arrayref containing allowed hashing methods. Valid options are C<apr1>, C<crypt>, 
C<plain>, C<md5> or C<sha>. By default all are allowed.

    allow => [ 'md5', 'sha' ]

=item * log

Any object that supports C<debug>, C<info>, C<error> and C<warn>.

    log => Log::Log4perl->get_logger('Authen::Simple::Passwd')

=back

=item * authenticate( $username, $password )

Returns true on success and false on failure. Authentication attempts with a username that begins with a 
hyphen C<-> will always return false.

=back

=head1 PASSWORD HASHING ALGORITHMS

=over 4

=item * DES Extended Format

Platform dependent. Should work on most UNIX-like and Win32 systems.

    #!/usr/bin/perl
    
    my $password  = 'DES Extended';
    my $salt      = '_0A7AYX6B4/SPbM9NK6k';
    my $supported = ( crypt( $password, $salt ) eq $salt ) ? 'yes' : 'no';
    
    print "DES Extended is supported: $supported\n";
    
=item * Modular Crypt Format

=over 8

=item * $1$ MD5

Platform independent.

=item * $2$ Blowfish

Platform dependent.

=item * $3$ NT-Hash

Platform dependent.

=back

=item * Traditional Crypt/DES

Platform dependent. Should work on most UNIX-like and Win32 systems.

    #!/usr/bin/perl
    
    my $password  = 'Traditional Crypt';
    my $salt      = 'X5XLgrevYDdLc';
    my $supported = ( crypt( $password, $salt ) eq $salt ) ? 'yes' : 'no';
    
    print "Traditional Crypt is supported: $supported\n";

=item * Apache

=over 8

=item * $apr1$

Platform independent.

=back

=item * LDAP Directory Interchange Format

=over 8

=item * {SHA}

Platform independent.

=back

=back

=head1 SEE ALSO

L<Authen::Simple>.

L<passwd(5)>.

L<crypt(3)>.

=head1 AUTHOR

Christian Hansen C<ch@ngmedia.com>

=head1 COPYRIGHT

This program is free software, you can redistribute it and/or modify 
it under the same terms as Perl itself.

=cut
