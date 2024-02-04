## The Nodogsplash project

Nodogsplash is a Captive Portal that offers a simple way to provide restricted access to the Internet by showing a splash page to the user before Internet access is granted.

It was derived originally from the codebase of the Wifi Guard Dog project.

Nodogsplash is released under the GNU General Public License.

* Original Homepage: [http://kokoro.ucsd.edu/nodogsplash](https://web.archive.org/web/20120108100828/http://kokoro.ucsd.edu/nodogsplash)
* Wifidog: https://github.com/wifidog
* GNU GPL: http://www.gnu.org/copyleft/gpl.html

The following describes what Nodogsplash does, how to get it and run it, and
how to customize its behavior for your application.

## Overview

**Nodogsplash** (NDS) is a high performance, small footprint Captive Portal, offering a simple splash page restricted Internet connection.

NoDogSplash is optimised for target devices with limited resources.

**If you want a more sophisticated authentication system** providing a dynamic web interface, you need [openNDS](https://github.com/openNDS/openNDS) rather than NoDogSplash.

**All modern mobile devices**, most desktop operating systems and most browsers now have a Captive Portal Detection (CPD) process that automatically issues a port 80 request on connection to a network. Nodogsplash detects this and serves its 'splash' web page.

The splash page in its most basic form, contains a *Continue* button. When the user clicks on it, access to the Internet is granted, subject to a preset time interval.

Nodogsplash does not currently support traffic control but is fully compatible with other stand alone systems such as Smart Queue Management (SQM).

## Split of Nodogsplash

Nodogsplash has been split into 2 projects:

* [OpenNDS](https://github.com/openNDS/openNDS) containing the FAS (Forward Authentication Service)
* [Nodogsplash](https://github.com/nodogsplash/nodogsplash) containing a minimal version.

OpenNDS has been forked of from version 4.x (commit 4bd2f00166ed17ac14f9b78037fce5725bd894ce).
Nodogsplash has been forked of from 3.x (commit 28541e787c989589bcd0939d3affd4029a235a3a).

The first version with different code bases is version 5.0

## Documentation

For full documentation please look at https://nodogsplashdocs.rtfd.io/

You can select either *Stable* or *Latest* documentation.

