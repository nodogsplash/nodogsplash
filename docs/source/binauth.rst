BinVoucher Option
=================

**Key: BinAuth**

**Value: /path/to/executable/script**

Authenticate a client by using an external program that get passed username and password, if supplied.
The exit code and output values decide if a client is to be authenticated.

For the following examples, setting `binauth` is set to `/etc/nds_auth.sh`.

Client enters a username 'Bill' and password 'tms':

.. code::

   /etc/nds_auth.sh client_auth 12:34:56:78:90 'Bill' 'tms'

The values of username and password passed to the script may be empty.
For the authentication to be successful, the exit code of the script must be 0. Up to three return values are accepted; the number of seconds the session should last, the maximum number of upload bytes and the number of download bytes. If no seconds are given, setting SessionTimeout will be used. Upload and download bytes have no effect right now.

Client is deauthenticated due to inactivity:

.. code::

   /etc/nds_auth.sh idle_timeout <mac> <incoming_bytes> <outgoing_bytes> <duration_seconds>

Client is deauthenticated due to the session end:

.. code::

   /etc/nds_auth.sh session_end <mac> <incoming_bytes> <outgoing_bytes> <duration_seconds>

**Example script:**

.. code-block:: sh

    #!/bin/sh

    METHOD="$1"
    MAC="$2"

    case "$METHOD" in
      "client_auth")
        USERNAME="$3"
        PASSWORD="$4"
        if [ "$USERNAME" = "Bill" -a "$PASSWORD" = "tms" ]; then
          # Allow client to access the Internet for one hour (3600 seconds)
          # Further values are upload and download limits in bytes. 0 for no limit.
          echo 3600 0 0
        fi
        ;;
      "idle_timeout")
        INGOING_BYTES="$3"
        OUTGOING_BYTES="$4"
        DURATION_SECONDS="$5"
        # The client was deauthenticated after DURATION_SECONDS seconds because of inactivity
        ;;
      "session_end")
        INGOING_BYTES="$3"
        OUTGOING_BYTES="$4"
        DURATION_SECONDS="$5"
        # The client was deauthenticated after DURATION_SECONDS seconds because of the session ended
        ;;
    esac

    exit 0
