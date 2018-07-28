BinVoucher Option
=================

**Key: BinVoucher**

**Value: /path/to/executable/script**

This feature offers an alphanumeric token for the end user to authenticate
against custom services. The services are called via script or tool.

Example calls by Nodogsplash when binvoucher is set to `/etc/nds_auth.sh`.
Client enters a voucher `A7SU5`:
```
/etc/nds_auth.sh client_auth 12:34:56:78:90 A7SU5
```
For the authentication to be successfull, the exit code of the script must be 0 and the output to stdout must be the number of seconds > 0. The maximum number of upload and download bytes can also be given, but the traffic shaping feature uses the imq queue, which is not prsent anymore in modern Linux kernels.

Client is deauthenticated due to inactivity when the session is 632 seconds old:
```
/etc/nds_auth.sh timeout_deauth 12:34:56:78:90 A7SU5 623
```

Client is deauthenticated due to the session limit when the session is 3600 seconds old:
```
/etc/nds_auth.sh session_deauth 12:34:56:78:90 A7SU5 623
``

**Example script:**

.. code-block:: sh

    #!/bin/sh

    METHOD="$1"
    MAC="$2"
    VOUCHER="$3"
    DURATION="$4"

    case "$METHOD" in
      "client_auth")
        if [ "$VOUCHER" = "abc" ]; then
          # Allow client to access the Internet for one hour (3600 seconds)
          # Further values are upload and download limit in bytes (0 for none).
          echo 3600 0 0
        fi
        ;;
      "timeout_deauth")
        # The client was deauthenticated after $DURATION seconds because of inactivity
        ;;
      "session_deauth")
        # The client was deauthenticated after $DURATION seconds because of the session ended
        ;;
    esac

exit 0
