package Authen::Simple::Passwd;

use strict;
use warnings;
use bytes;
use base 'Authen::Simple::Adapter';

use Config           qw[];
use Fcntl            qw[:flock];
use IO::File         qw[O_RDONLY];
use Params::Validate qw[];

our $VERSION = 0.5;

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
        optional  => 1,
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

    unless ( $self->check_password( $password, $encrypted ) ) {

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

This method takes a hash of parameters. The following options are valid:

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

=item * log

Any object that supports C<debug>, C<info>, C<error> and C<warn>.

    log => Log::Log4perl->get_logger('Authen::Simple::Passwd')

=back

=item * authenticate( $username, $password )

Returns true on success and false on failure. Authentication attempts with a username that begins with a 
hyphen C<-> will always return false.

=back

=head1 SEE ALSO

L<Authen::Simple>.

L<Authen::Simple::Password>.

L<passwd(5)>.

=head1 AUTHOR

Christian Hansen C<ch@ngmedia.com>

=head1 COPYRIGHT

This program is free software, you can redistribute it and/or modify 
it under the same terms as Perl itself.

=cut
