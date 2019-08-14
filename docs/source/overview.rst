Overview
########

**NoDogSplash** (NDS) is a high performance, small footprint Captive Portal, offering by default a simple splash page restricted Internet connection, yet incorporates an API that allows the creation of sophisticated authentication applications.

Captive Portal Detection (CPD)
******************************
 All modern mobile devices, most desktop operating systems and most browsers now have a CPD process that automatically issues a port 80 request on connection to a network. NDS detects this and serves a special "**splash**" web page to the connecting client device.

Provide simple and immediate public Internet access
***************************************************
 NDS provides two pre-installed methods.

 * **Click to Continue**. A simple static web page with template variables (*default*). This provides basic notification and a simple click/tap to continue button.
 * **username/email-address login**. A simple dynamic set of web pages that provide username/email-address login, a welcome page and logs access by client users. (*Installed by default and enabled by un-commenting a line in the configuration file*)

  Customising the page seen by users is a simple matter of editing the respective html or script files.

Write Your Own Captive Portal.
******************************
 NDS can be used as the "Engine" behind the most sophisticated Captive Portal systems using the tools provided.

 * **Forward Authentication Service (FAS)**. FAS provides pre-authentication user validation in the form of a set of dynamic web pages, typically served by a web service independent of NDS, located remotely on the Internet, on the local area network or on the NDS router.
 * **PreAuth**. A special case of FAS that runs locally on the NDS router with dynamic html served by NDS itself. This requires none of the overheads of a full FAS implementation and is ideal for NDS routers with limited RAM and Flash memory.
 * **BinAuth**. A method of running a post authentication script or extension program.