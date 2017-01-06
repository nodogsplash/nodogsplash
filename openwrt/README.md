### Install from OpenWrt feeds

The NoDogSplash OpenWrt package is part of the [openwrt-routing](https://github.com/openwrt-routing/packages) feed and can be installed using opkg:

```
opkg update
opkg install nodogsplash
```

## Build from Sources

To build NoDogSplash from sources and to create your own .ipk
package (similar to Debians .deb files), you have to build an OpenWRT image.
To build the firmware you need a Unix console to enter commands into.

Install the dependencies of the build environment (Debian/Ubuntu):
```
sudo apt-get install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
```

Build Commands:
```
git clone git://git.openwrt.org/openwrt.git
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a
./scripts/feeds uninstall nodogsplash

git clone git://github.com/nodogsplash/nodogsplash.git
cp -rf nodogsplash/openwrt/nodogsplash package/
rm -rf nodogsplash/

make defconfig
make menuconfig
```

At this point select the appropiate "Target System" and "Target Profile"
depending on what target chipset/router you want to build for.
Now select the NoDogSplash package in "Network ---> Captive Portals".

Now compile/build everything:

```
make
```

The images and all *.ipk packages are now inside the bin/ folder.
You can install the NoDogSplash .ipk using "opkg install &lt;ipkg-file&gt;"
on the router or just use the whole image.

For details please check the OpenWRT documentation.

## Build from local sources

You might want to use your own source location and not the remote respository.
To do this you need to checkout the repository yourself and commit your changes locally:

```
git clone git://github.com/nodogsplash/nodogsplash.git
cd nodogsplash
... apply your changes
git commit -am "my change"
```

Now create a symbolic link in the NoDogSplash package folder using the abolute path:

```
ln -s /my/own/project/folder/nodogsplash/.git feeds/routing/nodogsplash/git-src
make package/nodogsplash/{clean,compile} V=s

```

Also make sure to enable

```
"Advanced configuration options" => "Enable package source tree override"
```

in the menu when you do `make menuconfig`.
