vusb-daemon handles USB device passthrough.  
It listens to dbus and udev for user, toolstack and device events.  
Then, according to the database-stored policy, it uses the vusb dom0 kernel module to trigger USB passthrough action.

See the wiki page for more information:
https://github.com/OpenXT/openxt/wiki/vUSB-daemon
