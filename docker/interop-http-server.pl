use strict;
use warnings;
use IO::Socket::INET;

my $server = IO::Socket::INET->new(
    LocalAddr => "127.0.0.1",
    LocalPort => 4242,
    Listen => 5,
    ReuseAddr => 1,
);
unless ($server) {
    # A server is already listening on this port; leave it running.
    exit 0 if $! =~ /in use/i;
    die "$!\n";
}

while (my $client = $server->accept()) {
    while (my $line = <$client>) {
        last if $line =~ /^\r?\n$/;
    }
    print {$client} "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\ninterop-http-ok";
    close $client;
}
