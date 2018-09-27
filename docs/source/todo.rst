TODO List
#########

Not all features are finished or working as properly or as efficiently as they should.
Here is a list of things that need to be improved:

* While (un-) block/trust/allow via the ndsctl tool take effect, the state object of the client in NDS is not affected.
  Both systems still need to be connected (in src/auth.c).

* Include blocked and trusted clients in the client list - so that they can be managed.

* Extend Status processing to display a page when a user's authentication is rejected, e.g. because the user exceeded a quota or is blocked etc.

* Implement Traffic control on a user by user basis. This functionality was originally available but has been broken for many years.

* The code in src/http_microhttpd.c has evolved from previous versions and possibly has some missed edge cases. It would benefit from a rewrite to improve maintainability as well as performance.

* ip version 6 is not currently supported by NDS. It is not essential or advantageous to have in the short term but should be added at some time in the future.
