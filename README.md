## 0. The Nodogsplash project

Nodogsplash is a Captive Portal that offers a simple way to provide restricted access to the Internet by showing a splash page to the user before Internet access is granted.

From version 5.0.0 it no longer supports the creation of sophisticated authentication applications. Instead, this functionality is provided by the openNDS package - https://github.com/openNDS/openNDS

It was derived originally from the codebase of the Wifi Guard Dog project.

Nodogsplash is released under the GNU General Public License.

* Mailing List: http://ml.ninux.org/mailman/listinfo/nodogsplash
* Original Homepage (no longer available): http://kokoro.ucsd.edu/nodogsplash
* Wifidog: http://dev.wifidog.org/
* GNU GPL: http://www.gnu.org/copyleft/gpl.html

The following describes what Nodogsplash does, how to get it and run it, and
how to customize its behaviour for your application.

## 1. Overview

**NoDogSplash** (NDS) is a high performance, small footprint Captive Portal, offering a simple splash page restricted Internet connection.

The alternate openNDS package provides a powerful API for developing custom Captive portal login pages ranging from a simple user login through to sophisticated multi site systems.
Details of openNDS can be found at:
https://opennds.readthedocs.io

**Captive Portal Detection (CPD)**

 All modern mobile devices, most desktop operating systems and most browsers now have a CPD process that automatically issues a port 80 request on connection to a network. NDS detects this and serves a special "**splash**" web page to the connecting client device.

**Provide simple and immediate public Internet access**

 NDS provides a simple templated splash page.

 This splash page provides basic notification and a simple click/tap to continue button.

  Customising the page seen by users is a simple matter of editing the respective html.

## 2. Documentation

For full documentation please look at https://nodogsplashdocs.rtfd.io/

You can select either *Stable* or *Latest* documentation.

---

Email contact: nodogsplash (at) ml.ninux.org
