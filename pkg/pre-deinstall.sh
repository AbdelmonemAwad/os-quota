#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) before the files of os-quota are removed. The scripts that empty the table and take the
# alias out are packaged files: by post-deinstall they are gone. So a read in progress is ended, the
# table emptied while its alias is there - what the coprocessor dropped for it handed back to the host,
# once (configctl quota leave) - and the alias taken out of Firewall: Aliases and XGS:
# Settings' cut list through OPNsense's own models - switched off instead where a rule or a setting
# still names it.
#
# pkg runs the old package's pre-deinstall in an upgrade too, where nothing is to go: the counts, the
# alias and the table stay, and the new package's post-install does the Apply with the new code.
# PKG_UPGRADE is set in that case and no other.
if [ -n "${PKG_UPGRADE}" ]; then
	exit 0
fi

# the brackets keep the pattern from matching the shell that runs this text
/bin/pkill -f '/usr/local/opnsense/scripts/[q]uota/' 2> /dev/null || true

if [ -f /usr/local/sbin/configctl ]; then
	/usr/local/sbin/configctl quota leave > /dev/null 2>&1 || true
	/usr/local/sbin/configctl quota remove > /dev/null 2>&1 || true
fi
