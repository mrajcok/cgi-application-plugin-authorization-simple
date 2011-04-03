package CGI::Application::Plugin::Authorization::Simple;
# requires runmode authz_error() to be defined for handling errors.
# Synopsis:
#
#   package CommentManager;
#   use base 'CGI::Application';
#   use CGI::Application::Plugin::Authorization::Simple;
#   sub authz_check_owner {		# ensure user is comment owner
#	  my $self = shift;
#     ...
#   }
#   sub edit :Runmode :Authen :Authz(owner) { ... }
# "owner" turns into a call to authz_check_owner() when the runmode is called

use strict;
use warnings;
use base 'Exporter';
use Carp;
use Attribute::Handlers;
our @EXPORT = qw(authorize);
our $VERSION = '1.0';
my %runmode_refs;

# Run this handler twice:
# in CHECK (default) when we have the $symbol name, and also in BEGIN
# because CHECK does not work in mod_perl, starman, etc. but BEGIN does.
# Note that $symbol is set to 'ANON' under mod_perl, starman in BEGIN phase.
sub CGI::Application::Authz : ATTR(CODE,RAWDATA,BEGIN,CHECK) {
	my ($package, $symbol, $referent, $attr, $data, $phase) = @_;
	# $data should contain the suffix of an authorization method to call
#	print "authz p=$phase s=$symbol r=$referent d=$data\n";
	$runmode_refs{$referent} = $data || undef;
}
sub authorize {	# prerun check
	my($self, $rm) = @_;
	# Note, this method can not be installed as a hook/callback, since we need
	# to execute BaseCgiApp::cgiapp_prerun() first.  If installed as
	# a callback, it would get called before cgiapp_prerun().
	my $rm_ref = $self->can($rm);
	return if ! $rm_ref;
	return if !exists $runmode_refs{$rm_ref};
	my $authz_check_rm = 'authz_check_' . $runmode_refs{$rm_ref};
	croak "authz runmode $authz_check_rm() not available" if ! $self->can($authz_check_rm);
	if($self->$authz_check_rm) {
		# passed authorization check
	} else {
		if(defined $self->param('authz_db_error')) {
			$self->prerun_mode('authz_db_error');
		} else {	# normal authz error
			$self->prerun_mode('authz_error');
		}
	}
}
1
