# vusb-daemon
Partial rewrite of OpenXT's xc-vusb-daemon

## How to build
- In your OpenXT OpenEmbedded tree, edit <code>repos/xenclient-oe/recipes-openxt/xenclient/vusb/vusb-daemon_git.bb</code>  
Replace <code>git://${OPENXT_GIT_MIRROR}/xc-vusb-daemon.git</code>  
with <code>git://github.com/jean-edouard/vusb-daemon.git</code>
- Also edit <code>repos/xenclient-oe/recipes-openxt/xenclient/vusb/files/xenclient-vusb.initscript</code>  
Replace <code>PROG=/usr/sbin/vusb_daemon</code>  
with <code>PROG=/usr/sbin/vusb-daemon</code>
- Rebuild using <code>./bb -c cleansstate vusb-daemon && ./bb vusb-daemon</code>

## How to test
- Install the resulting package from the previous step.
- Running <code>restorecon -F -R /</code> could be enough, but you may need to just set SELinux to permissive.
- Reboot
- Try passing USB devices to VMs
