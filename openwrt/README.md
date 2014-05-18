To inlcude NoDogSplash into your OpenWRT image or to create
an .ipk package (equivalent to Debians .deb files),
you have to build an OpenWRT image.
These steps were tested using OpenWRT-"Attitude Adjustment":

<pre>
git clone git://git.openwrt.org/12.09/openwrt.git
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a
./scripts/feeds uninstall nodogsplash

git clone git://github.com/nodogsplash/nodogsplash.git
cp -rf nodogsplash/openwrt/nodogsplash package/
rm -rf nodogsplash/

make defconfig
make menuconfig
</pre>

At this point select the appropiate "Target System" and "Target Profile"
depending on what target chipset/router you want to build for.
To get an *.ipk file you also need to select "Build the OpenWrt SDK"

Now compile/build everything:

<pre>
make
</pre>

The images and all *.ipk packages are now inside the bin/ folder.
You can install the NoDogSplash .ipk using "opkg install &lt;ipkg-file&gt;"
on the router or just use the whole image.

For details please check the OpenWRT documentation.

### Note for developers

## Build Notes

You might want to use your own source location and not the remote respository.
To do this you need to checkout the repository yourself and commit your changes locally:

<pre>
git clone git://github.com/nodogsplash/nodogsplash.git
cd nodogsplash
... apply your changes
git commit -am "my change"
</pre>

Now create a symbolic link in the NoDogSplash package folder using the abolute path:

<pre>
ln -s /my/own/project/folder/nodogsplash/.git openwrt/package/nodogsplash/git-src
</pre>

Also make sure to enable

<pre>
"Advanced configuration options" => "Enable package source tree override"
</pre>

in the menu when you do `make menuconfig`.
