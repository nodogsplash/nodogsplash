Overview
########

Nodogsplash offers a solution to this problem: You want to provide controlled
and reasonably secure public access to an internet connection; and while you
want to require users to give some acknowledgment of the service you are
providing, you don't need or want the complexity of user account names and
passwords and maintaining a separate database-backed authentication server.
When installed and running, Nodogsplash implements a simple 'authentication'
protocol. First, it detects any user attempting to use your internet connection
to request a web page. It captures the request, and instead serves back a
'splash' web page using its own builtin web server. The splash page contains a
link which, when the user clicks on it, opens limited access for them to the
internet via your connection, beginning by being redirected to their originally
requested page. This access expires after a certain time interval.
Nodogsplash also permits limiting the aggregate bandwidth provided to users, if
you don't want to grant all of your available upload or download bandwidth.
Specific features of Nodogsplash are configurable, by editing the configuration
file and the splash page. The default installed configuration may be all you
need, though.
