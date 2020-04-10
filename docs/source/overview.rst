Overview
########

**NoDogSplash** (NDS) is a high performance, small footprint Captive Portal, offering a simple splash page restricted Internet connection.

The alternate openNDS package provides a powerful API for developing custom Captive portal login pages ranging from a simple user login through to sophisticated multi site systems.
Details of openNDS can be found at:
https://opennds.readthedocs.io

Captive Portal Detection (CPD)
******************************
 All modern mobile devices, most desktop operating systems and most browsers now have a CPD process that automatically issues a port 80 request on connection to a network. NDS detects this and serves a special "**splash**" web page to the connecting client device.

Provide simple and immediate public Internet access
***************************************************
 NDS provides a simple templated splash page.

 This splash page provides basic notification and a simple click/tap to continue button.

  Customising the page seen by users is a simple matter of editing the respective html.