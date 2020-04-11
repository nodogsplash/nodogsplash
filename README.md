## 0. The NoDogSplash project

NoDogSplash is a Captive Portal that offers a simple way to provide restricted access to the Internet by showing a splash page to the user before Internet access is granted.

**From version 5.0.0**, NoDogSplash supports only simple templated splash pages.

The creation of sophisticated authentication applications is now supported by the **openNDS package** to be found at:

https://github.com/openNDS/openNDS

This change ensures that NoDogSplash can be optimised for running on devices with very low resources without being compromised by continuing enhancement of Forwarding Authentication Services (FAS).

NoDogSplash was derived originally from the codebase of the Wifi Guard Dog project.

NoDogSplash is released under the GNU General Public License.

* Mailing List: http://ml.ninux.org/mailman/listinfo/nodogsplash
* Original Homepage (no longer available): http://kokoro.ucsd.edu/nodogsplash
* Wifidog: http://dev.wifidog.org/
* GNU GPL: http://www.gnu.org/copyleft/gpl.html

The following describes what NoDogSplash does, how to get it and run it, and how to customize its behaviour for your application.

## 1. Overview

**NoDogSplash** (NDS) is a high performance, small footprint Captive Portal, offering a simple splash page restricted Internet connection.

The alternate openNDS package provides a powerful API for developing custom Captive portal login pages ranging from a simple user login through to sophisticated multi site systems.
Details of openNDS can be found at:
https://opennds.readthedocs.io

**Captive Portal Detection (CPD)**

 All modern mobile devices, most desktop operating systems and most browsers now have a CPD process that automatically issues a port 80 request on connection to a network. NDS detects this and serves a special "**splash**" web page to the connecting client device.

**Provide Simple and Immediate Public Internet Access Control**

 NoDogSplash provides a simple templated splash page.

 This splash page enables basic client notification and a simple click/tap to continue button.

  Customising the page seen by clients is a simple matter of editing the respective html.

## 2. Documentation

For full documentation please look at https://nodogsplashdocs.rtfd.io/

You can select either *Stable* or *Latest* documentation.

---

Email contact: nodogsplash (at) ml.ninux.org
