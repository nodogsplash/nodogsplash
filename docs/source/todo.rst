TODO List
#########

Not all features are finished or working as properly as they should.
Here is a list of things that need to be improved:

* While (un-) block/trust/allow via the ndsctl tool take effect, the state object of the client in NDS is not affected.
  Both systems still need to be connected (in src/auth.c).

* Show a site when the users authentication was rejected, e.g. because the user exeeded the quota

* Traffic control is still broken since a long time now.

* The code in src/http_microhttpd.c is a mess that has probably a lot of missed edge cases.

* Include blocked and trusted clients in the client list - so that they can be managed.
