
To create a Debian package of NoDogSplash (a *.deb file),
you first need to have installed the following programs and libraries:

```
apt-get install build-essential debhelper devscripts hardening-includes
```

Run this command in the repository root folder to create the package:

```
dpkg-buildpackage
```

The package will be created in the parent directory.


Use this command if you want to create an unsigned package:

```
dpkg-buildpackage -b -rfakeroot -us -uc
```
