BinAuth Option
=================

**Key: BinAuth**

**Value: /path/to/executable/script**

Authenticate a client using an external program that get passed the (optional) username and password value.
The exit code and output values of the program decide if and how a client is to be authenticated.

The program will also be called on client authentication and deauthentication.

For the following examples, `binauth` is set to `/etc/nds_auth.sh` in nodogsplash.conf:

.. code-block:: sh

    #!/bin/sh

    METHOD="$1"
    MAC="$2"

    case "$METHOD" in
      auth_client)
        USERNAME="$3"
        PASSWORD="$4"
        if [ "$USERNAME" = "Bill" -a "$PASSWORD" = "tms" ]; then
          # Allow client to access the Internet for one hour (3600 seconds)
          # Further values are upload and download limits in bytes. 0 for no limit.
          echo 3600 0 0
          exit 0
        else
          # Deny client to access the Internet.
          exit 1
        fi
        ;;
      client_auth|client_deauth|idle_deauth|timeout_deauth|ndsctl_auth|ndsctl_deauth|shutdown_deauth)
        INGOING_BYTES="$3"
        OUTGOING_BYTES="$4"
        SESSION_START="$5"
        SESSION_END="$6"
        # client_auth: Client authenticated via this script.
        # client_deauth: Client deauthenticated by the client via splash page.
        # idle_deauth: Client was deauthenticated because of inactivity.
        # timeout_deauth: Client was deauthenticated because the session timed out.
        # ndsctl_auth: Client was authenticated by the ndsctl tool.
        # ndsctl_deauth: Client was deauthenticated by the ndsctl tool.
        # shutdown_deauth: Client was deauthenticated by Nodogsplash terminating.
        ;;
    esac

The `SESSION_START` and `SESSION_END` values are the number of seconds since 1970 or may be 0 for unknown/unlimited.

The splash.html page contains the following code:

.. code-block:: html

    <form method='GET' action='$authaction'>
    <input type='hidden' name='tok' value='$tok'>
    <input type='hidden' name='redir' value='$redir'>
    username: <input type='text' name='username' value='' size='12' maxlength='12'>
    <br>
    password: <input type='password' name='password' value='' size='12' maxlength='10'>
    <br>
    <input type='submit' value='Enter'>
    </form>

If a client enters a username 'Bill' and password 'tms', then the configured `binauth` script is executed:

.. code::

   /etc/nds_auth.sh auth_client 12:34:56:78:90 'Bill' 'tms'

For the authentication to be successful, the exit code of the script must be 0. The output can be up to three values. First the number of seconds the client is to be authenticated, second and third the maximum number of upload and download bytes limits. Values not given to NDS will resort to default values. Note that the traffic shaping feature that uses the upload/download values does not work right now.

After initial authentication by the script, Nodogsplash will immediately acknowlege by calling the binauth script again with:

.. code::

   /etc/nds_auth.sh client_auth 12:34:56:78:90 <incoming_bytes> <outgoing_bytes> <session_start> <session_end>

Nodogsplash will also call the script when the client is authenticated and deauthenticated in general.
