#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-quota are in place, on install and on upgrade alike.
# tools/make-package.sh inlines it into the package manifest. The first blocks and the registration
# are what every OPNsense plugin runs; the chmod lines and syntax checks of install/install.sh are
# not repeated, for the reasons os-netreport's post-install gives. No package is needed beside it:
# pfctl, Python and PHP are OPNsense's own.

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

install -d -o root -g wheel -m 0750 /var/db/os-quota

if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
	/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/Quota
fi

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php install os-quota > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_INSTALL
fi

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. The menu file is not one of the package's files; place-menu.sh writes it and says which it
# chose.
WHERE=
if [ -x /usr/local/opnsense/scripts/quota/place-menu.sh ]; then
	WHERE=$(/usr/local/opnsense/scripts/quota/place-menu.sh) || WHERE=
fi

# The page's Apply, as install/install.sh does it: off by default, so on a first install only the
# filter and cron take the plugin in; on an upgrade with the plugin on, the alias, the filter and a read.
STATE=
if [ -f /usr/local/sbin/configctl ]; then
	ON=
	if /usr/local/bin/python3 /usr/local/opnsense/scripts/quota/settings.py enabled 2> /dev/null | grep -q '"enabled": true'; then
		ON=yes
	fi
	if [ -z "${ON}" ]; then
		/usr/local/sbin/configctl quota flush > /dev/null 2>&1 || true
	fi
	/usr/local/sbin/configctl quota apply > /dev/null 2>&1 || true
	/usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true
	/usr/local/sbin/configctl cron restart > /dev/null 2>&1 || true
	if [ -n "${ON}" ]; then
		/usr/local/sbin/configctl quota account > /dev/null 2>&1 || true
		STATE=" (counting)"
	else
		/usr/local/sbin/configctl quota gone > /dev/null 2>&1 || true
		STATE=" (off until it is turned on in Settings)"
	fi
fi

case "${WHERE}" in
xgs)	echo "Quotas installed: the page is at XGS > Quotas${STATE}" ;;
own)	echo "Quotas installed: the page is at Firewall > Quotas${STATE}" ;;
*)	echo "Quotas installed${STATE}; its menu file was not written: run /usr/local/opnsense/scripts/quota/place-menu.sh" ;;
esac
