use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Linux::ACL',
    AUTHOR              => q{Yuriy Nazarov <nazarov@cpan.org>},
    VERSION_FROM        => 'lib/Linux/ACL.pm',
    ABSTRACT_FROM       => 'lib/Linux/ACL.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Linux-ACL-*' },
);
