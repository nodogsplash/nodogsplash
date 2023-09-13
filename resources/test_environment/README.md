# NoDogSplash Test Environment

Often it is helpful to be able to test NoDogSplash on a local computer,
without affecting the normal operations.

The [nds_test_environment.sh](./nds_test_environment.sh) script allows
to set up such an environment using Linux network namespaces.

Two namespaces allow to simulate a two clients and start a web browser in them.
One namespace is for running NoDogSplash.

![Namespace Structure](nds_test_environment.png)
