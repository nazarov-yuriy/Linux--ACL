package Linux::ACL;

use warnings;
use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(getfacl);
our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Linux::ACL', $VERSION);

1;
=head1 NAME

Linux::ACL - The great new Linux::ACL!

=head1 VERSION

Version 0.01

=cut




=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Linux::ACL;

    my $foo = Linux::ACL->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS

=head2 function1

=cut

=head1 AUTHOR

Yuriy Nazarov, C<< <nazarov at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-linux-acl at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Linux-ACL>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Linux::ACL


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Linux-ACL>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Linux-ACL>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Linux-ACL>

=item * Search CPAN

L<http://search.cpan.org/dist/Linux-ACL/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2013 Yuriy Nazarov.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut