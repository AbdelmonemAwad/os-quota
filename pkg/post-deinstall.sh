#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-quota have been removed; not during an upgrade. The table was
# emptied and the alias taken out in pre-deinstall, while the files that do it were there. Kept: the
# settings in config.xml.

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-quota > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# The menu file place-menu.sh wrote is not one of the package's files, so pkg left it, and the
# model's directory with it. The menu is cached by PHP in /var/lib/php/tmp on 26.7, in /tmp before.
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/Quota/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/Quota/Menu /usr/local/opnsense/mvc/app/models/OPNsense/Quota 2>/dev/null || true
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml

# Nor what Python compiles beside a script it imports, which would keep the scripts' directory; nor the
# counts and the last read in /var/db - after a read cron started before pkg took its line away has been
# ended: the scripts are gone, so none starts after this. The plugin's directories go once empty.
/bin/pkill -f '/usr/local/opnsense/scripts/[q]uota/' 2> /dev/null || true
rm -rf /usr/local/opnsense/scripts/quota/__pycache__ /var/db/os-quota
for d in /usr/local/opnsense/scripts/quota /usr/local/opnsense/mvc/app/library/OPNsense/Quota; do
	[ -d "${d}" ] && find "${d}" -depth -type d -empty -delete 2> /dev/null
done

# the filter without the hook - the block rules gone - and cron without the minute's run
[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true
[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl cron restart > /dev/null 2>&1 || true

# The table, taken out of pf when no rule uses it: a table outlives its alias and goes on holding the
# addresses (os-blocklists, 2026-10-29). One whose alias is still in Firewall: Aliases - switched off, as
# something names it - is OPNsense's to keep.
if ! grep -q "<name>quota_over</name>" /conf/config.xml 2> /dev/null; then
	/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 == "quota_over" && $1 !~ /r/ { print $2 }' |
	while read -r table; do
		/sbin/pfctl -t "${table}" -T kill > /dev/null 2>&1 || true
	done
fi

echo "Quotas removed; its settings stay in config.xml"
