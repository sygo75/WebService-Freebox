use strict;
use warnings;

package WebService::Freebox;

# ABSTRACT: Freebox API wrappers.

=head1 SYNOPSIS

Interface to Freebox (see L<http://en.wikipedia.org/wiki/Freebox>) API.

Notice that even creating objects of this class will not work if Freebox is
not available on the network (i.e. if request to L<http://mafreebox.freebox.fr/api_version>
fails), so it is only useful for customers of the French ISP called "Free" who
do have access to Freebox.


To use the API, a unique authorization token must be obtained for every new
installation of the given application, which requires the user to allow API
access for this application by physically pressing the Freebox buttons. Once
this is done, the token needs to be saved and reused the next time a
C<WebService::Freebox> object needs to be created:

    # First time, if app token is not available:
    my $fb = WebService::Freebox->new(app_id => 'org.example.testapp', app_version => '1.0');
    my $app_token = $fb->authorize('Test App', 'Device to authorize');
    # save $app_token somewhere, e.g. using Config::XXX module

    # Subsequent runs:
    my $fb = WebService::Freebox->new(app_id => 'org.example.testapp', app_version => '1.0', app_token => $app_token);

Notice that the app token must be kept secret as it is sufficient to
authenticate with the Freebox.

Additionally, a session must be opened before using the API. The session token
is ephemeral, unlike the app token, but still needs to be saved and reused if
possible to avoid reopening the session every time unnecessarily:

    # If no previous session token:
    my $session_token = $fb->start_session();

    # Reuse the previous session token if possible (if it doesn't work, a new
    # session is opened):
    $fb->start_session($session_token);

Finally, once the session is opened, the API can be used:

    my $sc = $fb->get_system_config();
    say "Freebox is up for $sc->{uptime}."

=cut

use Mouse;

use Digest::SHA qw(hmac_sha1_hex);
use JSON;
use REST::Client;

# VERSION

has app_id => ( is => 'ro', isa => 'Str', required => 1 );
has app_version => ( is => 'ro', isa => 'Str', required => 1 );

has app_token => ( is => 'ro', isa => 'Str' );

has _client => ( is => 'ro', builder => '_create_client' );
has _api_version => ( is => 'ro', builder => '_get_api_version' );

# Create the REST client we're going to use for all our requests.
sub _create_client {
    my $self = shift;

    my $c = REST::Client->new(host => 'http://mafreebox.freebox.fr');
    $c->addHeader('Accept', 'application/json');
    $c->addHeader('Content-Type', 'application/json');

    return $c;
}

# Wrapper around REST::Client request() checking for errors: the first
# argument is the error message given if the request failed.
sub _request {
    my ($self, $errmsg, $request, $url, $body) = @_;

    my $c = $self->_client;
    $c->request($request, $url, $body);

    my $errcode = $c->responseCode();
    if ($errcode != 200) {
        die qq{$errmsg ("$request $url" failed with HTTP error $errcode).\n}
    }

    return decode_json $c->responseContent()
}

# Helper for making normal API requests, i.e. all except for the initial one,
# checking for the Freebox presence and detecting the API version.
sub _api_request {
    my ($self, $errmsg, $request, $url, @rest) = @_;
    $self->_request($errmsg, $request, '/api/v' . $self->_api_version . "/$url", @rest);
}

# Detect the Freebox and get the API version used by it.
sub _get_api_version {
    my $self = shift;

    my $res = $self->_request('Freebox v6 not detected', 'GET', '/api_version');

    my $api_version = $res->{api_version};
    die "Unexpected Freebox API version $api_version.\n" if $api_version !~ '[23].0';

    # We need to use just the major number in the HTTP requests.
    $api_version =~ s/\.\d$//;

    return $api_version;
}


=method CONSTRUCTOR

C<app_id> and C<app_version> values must be specified when creating the object.
C<app_token> may be also specified here or obtained from L<authorize()> later
(and saved for future use).


    my $fb = WebService::Freebox->new(app_id => 'My App',
                                      app_version => '1.0',
                                      app_token=> '...64 alphanumeric characters ...');

The validity of the token is not checked here but using an invalid token will
result in a failure in C<start_session()> later.

=cut


=method authorize

Request an authorization token for the app:

    my $app_token = $fb->authorize('Test App', 'Device to authorize');

This method must be called before doing anything else with this object if no
valid token was supplied when constructing it and its return value must be
saved and reused in the future, to avoid asking the user once again.

Notice that it may take a long time to return as it blocks until the user
physically presses a button on the Freebox to either accept or deny the
authorization request.

=cut

sub authorize {
    my ($self, $app_name, $device_name) = @_;

    my $app_id = $self->app_id;

    my $res = $self->_api_request(
            'Requesting authorization failed',
            'POST',
            'login/authorize/',
            encode_json({
                app_id => $app_id,
                app_name => $app_name,
                app_version => $self->app_version,
                device_name => $device_name
            })
        );

    my $app_token = $res->{result}{app_token};

    my $track_id = $res->{result}{track_id};
    while (1) {
        $res = $self->_api_request(
            'Waiting for authorization failed',
            'GET',
            "login/authorize/$track_id"
        );

        last if $res->{result}{status} ne 'pending';

        sleep 1;
    }

    die "Failed to obtain authorization for $app_id: $res->{result}{status}.\n"
        unless $res->{result}{status} eq 'granted';

    return $app_token
}

__PACKAGE__->meta->make_immutable();
