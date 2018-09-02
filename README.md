## 0. The Nodogsplash project

Nodogsplash is a Captive Portal that offers a simple way to provide restricted access to the Internet by showing a splash page to the user before Internet access is granted.

It also incorporates an API that allows the creation of sophisticated authentication applications.

It was derived originally from the codebase of the Wifi Guard Dog project.

Nodogsplash is released under the GNU General Public License.

* Mailing List: http://ml.ninux.org/mailman/listinfo/nodogsplash
* Original Homepage: http://kokoro.ucsd.edu/nodogsplash
* Wifidog: http://dev.wifidog.org/
* GNU GPL: http://www.gnu.org/copyleft/gpl.html

The following describes what Nodogsplash does, how to get it and run it, and
how to customize its behavior for your application.

## 1. Overview

**Nodogspash** (NDS) is a high performance, small footprint Captive Portal, offering by default a simple splash page restricted Internet connection, yet incorporates an API that allows the creation of sophisticated authentication applications.

**If you want to provide simple and immediate public access** to an Internet connection with users giving some acknowledgment of the service, Nodogsplash does this by default.
Customising the page seen by users is a simple matter of editing the simple default html splash page file.

**If you want to enforce use of a set of preset usernames** and passwords with perhaps a limited connection time, the addition of a simple shell script is all that is required.

**If you want a more sophisticated authentication system** providing a dynamic web interface you can do that too by providing your own web service written in a language such as php running on its own server.

**Taking this to the extreme**, if you want to link Nodogsplash to your own centralised Internet based authentication service with user account self generation and access charging, you can do that too, or anything in between.

All modern mobile devices, most desktop operating systems and most browsers now have a Captive Portal Detection process that automatically issues a port 80 request on connection to a network. Nodogsplash detects this and serves a 'splash' web page.

The splash page in its most basic form, contains a Continue button. When the user clicks on it, access to the internet is granted subject to a preset time interval.

Nodogsplash does not currently support traffic control but is fully compatible with other stand alone systems such as SQM scripts.

**Nodogsplash supports multiple means of authentication**:

- Click the submit button (default)
- Call an external script that may accept username/password and set session durations per user.
- Forwarding authentication to an external service


## 2. Documentation

For additonal documentation please look at https://nodogsplashdocs.rtfd.io/

---

Email contact: nodogsplash (at) ml.ninux.org
