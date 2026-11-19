#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Quotas plugin: the table emptied, the alias quota_over taken out of Firewall: Aliases -
# switched off instead where a rule or a setting still names it - and out of XGS: Settings' cut list, its
# files, its state in /var/db/os-quota (the counts with it), and the table taken out of pf. Kept: the
# settings in config.xml.

# a read in progress, then the table and the alias, while the files that empty and remove them are there;
# the brackets keep the pattern from matching a shell that carries this text
/bin/pkill -f '/usr/local/opnsense/scripts/[q]uota/' 2> /dev/null || true
configctl quota flush > /dev/null 2>&1 || true
configctl quota remove > /dev/null 2>&1 || true

# the hook, the boot's read and the minute's run, then everything else src/ lays down
rm -f /usr/local/etc/inc/plugins.inc.d/quota.inc
rm -f /usr/local/etc/rc.syshook.d/start/70-quota
rm -f /usr/local/etc/cron.d/quota
rm -rf /usr/local/share/os-quota
rm -f /usr/local/opnsense/service/conf/actions.d/actions_quota.conf
rm -rf /usr/local/opnsense/scripts/quota
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/Quota/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/Quota/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/Quota
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/Quota
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/Quota
rm -rf /usr/local/opnsense/mvc/app/library/OPNsense/Quota
# the counts and the last read
rm -rf /var/db/os-quota
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
# the filter without the hook: the block rules gone; cron without the minute's run
configctl filter reload skip_alias > /dev/null 2>&1 || true
configctl cron restart > /dev/null 2>&1 || true
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
