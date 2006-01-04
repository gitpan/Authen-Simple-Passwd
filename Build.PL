use strict;
use Module::Build;

my $build = Module::Build->new(
    license            => 'perl',
    module_name        => 'Authen::Simple::Passwd',
    requires           => {
        'Authen::Simple'   => 0,
        'Crypt::PasswdMD5' => 0,
        'Digest::MD5'      => 0,
        'Digest::SHA1'     => 0,
        'IO::File'         => 0
    },
    create_makefile_pl => 'traditional',
    create_readme      => 1
);

$build->create_build_script;
