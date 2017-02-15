BinVoucher Option
=================

**Key: BinVoucher**

**Value: /path/to/executable/script**

This feature offers an alphanumeric token for the end user to authenticate
against custom services. The services are called via script or tool.

There are two information passed to a script/tool as command-line parameters.

**Parameters:**

1) METHOD ( auth_verify | auth_update )
2) MAC ( 00:00:00:00:00 )
3) VOUCHER ( example: A7SU5 )
4) REMAINING_DURATION ( 3600 ) in seconds

**Example script:**

.. code-block:: bash

    #!/bin/bash

    FAILED_UPDATES_FILE="/tmp/nodogsplash.failed"
    DOMAIN="foo.com"
    KIOSK_MAC=$(cat /sys/class/net/eth1/address)
    CURL=$(which curl)
    METHOD="${1}"
    MAC="${2}"
    VOUCHER="${3}"
    REMAINING_DURATION="${4}"

    function check_failed_updates() {
      while IFS='' read -r line || [[ -n "${line}" ]]; do
      auth_update "${line}"
      done < "${FAILED_UPDATES_FILE}"
    }

    function auth_verify() {
      local url="http://${DOMAIN}/${KIOSK_MAC}/${VOUCHER}/verify_code"
      local json=$(${CURL} -s ${url})
      local state=$(echo ${json} | jsonfilter -e '@.success')

      if ${state}; then
        check_failed_updates
        return $(echo ${json} | jsonfilter -e '@.duration_remaining')
      else
        return 0
      fi
    }

    function auth_update() {
      local url="http://${DOMAIN}/${KIOSK_MAC}/${1}/update_duration"
      local json=$(${CURL} -s ${url})
      local state=$(echo ${json} | jsonfilter -e '@.success')

      if ${state}; then
        exit 0
      else
        echo "${1} ${2}" >> "${FAILED_UPDATES_FILE}"
        exit 1
      fi
    }

    if [ "$#" -lt 3 ]; then
      exit 1
    fi

    touch "${FAILED_UPDATES_FILE}"

    if [ "${METHOD}" == "auth_verify" ]; then
      auth_verify
      printf "%i 0 0" "${?}"
    elif [ "${METHOD}" == "auth_update" ]; then
      auth_update "${VOUCHER}" "${REMAINING_DURATION}"
    fi

    exit 0
