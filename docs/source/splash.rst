The Splash Page
###############

As you will see mentioned in the "How Nodogsplash (NDS) Works" section, an initial port 80 request is generated on a client device, either by the user manually browsing to an http web page, or, more usually, automatically by the client device's built in Captive Portal Detection (CPD).

This request is intercepted by NDS and an html Splash Page is served to the user of the client device to enable them to authenticate and obtain Internet access.

Types of Splash Page
********************

This Splash page can be one of the following:

* **A Static Web Page served by NDS:**

 A page generated from the basic splash.html file installed with NDS and includes Template Variables (as listed in the splash.html file). *This is the default configuration of a fresh installation of NDS.*

 A script or executable file can optionally be called by NDS for post authentication processing (see **BinAuth**).

 An example of the use of BinAuth is to check the Username and Password entered by a user into an authentication form supplied by the splash page.

* **A Dynamic Web Page served by NDS**

 A script or executable file is called by NDS immediately (without serving splash.html). The called script or executable will generate html code for NDS to serve in place of splash.html. (see **PreAuth**).

 This enables a dialogue with the client user, for dissemination of information, user response and authentication. 

 This is implemented using **FAS**, but *without the resource utilisation of a separate web server*, particularly useful for legacy devices with limited flash and RAM capacity.

* **A Dynamic Web Page served by an independent web server** on the same device as NDS, on the same Local Area Network as NDS, or on External Web Hosting Services.

  A script or executable file is called by NDS immediately (without serving splash.html). The called script or executable will generate html code to be served by an independent Web Server. (see FAS).

 This not only enables a dialogue with the client user, for dissemination of information, user response and authentication but also full flexibility in design and implementation of the captive portal functionality from a self contained system through to, for example, a fully integrated multi site system with a common database.

The Two Installed Basic Splash Pages
************************************

By default, two fully functional but basic "Splash" pages are installed. Simple config options allow you to choose which one to use.

 * The Simple "Click to Continue" splash page. (Default)
 * The "Username/Email-address" Login script.

*See the chapter on PreAuth for details on how to switch between these splash page types.*

In many instances, one or other of these simple methods will be all that is required, but the power of FAS, PreAuth and BinAuth can be used to create very sophisticated Captive Portal Systems.

Displaying Remote Content
*************************

FASand PreAuth can be used to display remote content on the client user login screen.
This is ideal for serving information, banner advertising etc.

An example is described in the **Displaying Remote Banner Images**
section of the PreAuth chapter.
