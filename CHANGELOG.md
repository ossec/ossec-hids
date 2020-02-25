**OSSEC changelog (3.6.0) <scott@atomicorp.com>**

**Release Maintainers**

Dan Parriott

Scott R. Shinn (http://www.atomicorp.com)


**Contributors on this release**

@ddpbsd Dan Parriot - Maintainer

@NicolasCARPi - Nocolas Carpi - Community

@cpu - Daniel McCarney - Community

@jknockaert - Jasper Knockaert - Community

@mwidman - Mike Widman - Community

@drsjb80 - Steve Beaty - Community
 

 
**General** 

@ddpbsd - ossec-dbd, Add help output to dbd, https://github.com/ossec/ossec-hids/pull/1833

@NicolasCARPi - INSTALL, updating depenency list, 
https://github.com/ossec/ossec-hids/pull/1832

@cpu - PCRE2, refuse to compile empty PCRE2 patterns, fix for Issue #1811,  https://github.com/ossec/ossec-hids/pull/1826

@cpu, analysisd, resolves CVE-2020-8442 Issue #1820, https://github.com/ossec/ossec-hids/pull/1825 

@cpu, analysisd, resolves CVE-2020-8443 Issue #1816, https://github.com/ossec/ossec-hids/pull/1824

@cpu, analysisd, resolves CVE-2020-8448 Issue #1815, https://github.com/ossec/ossec-hids/pull/1823

@cpu, Makefile, fix for DEBUGAD, https://github.com/ossec/ossec-hids/pull/1822

@jknockaert - dropbear rules, limit brute force rule to dropbear, https://github.com/ossec/ossec-hids/pull/1803

@mwidman, analysisd, Added non-standard Sophos UTM syslog timestamp format to pre-decoding. , https://github.com/ossec/ossec-hids/pull/1794

@drsjb80 - configs, Added authentication log file location for debian-based systems , https://github.com/ossec/ossec-hids/pull/1784

@ddpbsd - maild, Fix using a program to send mail, https://github.com/ossec/ossec-hids/pull/1783



**OSSEC changelog (3.5.0) <scott@atomicorp.com>**

**Release Maintainers**

Dan Parriott
Scott R. Shinn (http://www.atomicorp.com)

**Contributors on this release**

(@atomicturtle) Scott Shinn - Maintainer
(@ddpbsd) Dan Parriot - Maintainer
(@drsjb80) Steve Beaty - Community
(@sempervictus) Boris Lukashev - Community

**Release notes**

This would have been a minor 3.4.1 update if it wasnt for Boris Lukashev of https://www.sempervictus.com
contributing a much needed update to multi-line log analysis. Previous usage of multi-line in OSSEC in
the past was limited in processing events that did not use indentiation, a fairly common modern practice
for readability. This update adds a new type: multi-line_indented to handle this condition (Example: postgresql). 

Maintenance fixes in this release also address issue #1781, which affected maild when calling an external program, and add support for Fedora 31


Whats New:

(@atomicturtle) - Fedora 31 Support
(@sempervictus) - Implement multi-line collection for indented logs #1780
(@drsjb80) -  Added authentication log file location for debian-based systems #1784


General

(@ddpbsd) - Fix for Issue #1781, corrects issues with program sending mail




OSSEC changelog (3.4.0) <scott@atomicorp.com>

Release Maintainers

Dan Parriott
Scott R. Shinn (http://www.atomicorp.com)

Contributors on this release

(ddpbsd) Dan Parriot
(bchavet)
(binrush)
(mikeroyal)
(iasdeoupxe)
(aquerubin)
(Varstahl) 
(atomicturtle)
(jubois)
(almirb)

Release notes:
libevent handler https://github.com/ossec/ossec-hids/pull/1698 for dialog.
pcre2 rules


Whats New
Big changes in this release add support for the following new platforms: 
	- Debian buster
	- Fedora 30 
	- RHEL 8
	- (Much awaited!) Centos 8

Snapcraft.io universal linux packaging support (aka Snaps)  allow for a universal OSSEC package across multiple linux distributions.
	
Last but not least, ddpbsd has a long awaited fix for agentd/maild when ipv6 is disabled and/or hostnames are used instead of IPs in PR#1698. Thanks again to all our community contributors, and dedicated team members for their work on this release!

New Rules / Decoders

(aquerubin) Updated IPv4-dependent regexp in ownCloud decoders. PR#1697
(jubois) Fix Issue #1708 (Incorrect regex match) PR#1710
(jubois) PCRE2 rulefiles conversion PR#1711
(jubois) PCRE2 decoders conversion PR#1712
(aquerubin) Fix owncloud decoder PR#1724
(iasdeoupxe) Additional ownCloud decoder fix PR#1725
(iasdeoupxe) Second ownCloud decoder fix PR#1726
(ddpbsd) Adjust pix decoder and a firewall rule PR#1749
(binrush) Fixed missing same_source_ip in rule 11306 PR#1751 pureftpd
(ddpbsd) Addition to sshd rule, new ntpd rule PR#1757, 
(ddpbsd) Fix rule IDs PR#1760 -  openbsd_rules


General
(ddpbsd) syscheck, Try to silence the "Attempted to check FS status for" message. PR#1701
(ddpbsd) syscheck, Add some basic error handling to syscheck_control PR#1702
(ddpbsd) core, More unlink and fopen error handling in src/util PR#1703 
(almirb) active-response,Added Cloudflare active-response script. PR#1709
(Varstahl) cyslogd, csyslogd CEF – Remove duplicate parameters and fix discarded hashes PR#1713
(atomicturtle) - docs, Updating links, using https, conference links PR#1714
(Varstahl) cyslogd, Fix: csyslogd – CEF escaping / multi-line syslog 
(ddpbsd) core, Check return values for unlink(2) calls PR#1733 
(mikeroyal) packaging, snap build support PR#1737
(ddpbsd) core, Set PCRE2_SYSTEM to no by default. PR#1738
(ddpbsd) logtest, Remove leading space from field names PR#1741
(bchavet) analysisd, Verify Googlebot PR#1752 , this is a code function in generic_samples.c
(ddpbsd) analysisd, Free the lf->fields memory. PR#1758, fixes issue #1727
(ddpbsd) testing, Update some travis-ci bits PR#1759 - travis fixes



OSSEC changelog (3.3.0) <scott@atomicorp.com>

Release Maintainers

Dan Parriott
Scott R. Shinn (http://www.atomicorp.com)

Contributors on this release

almirb (Almir Bolduan)
aquerubin (Antonio Querubin)
atomicturtle (Scott R. Shinn)
Bob-Andrews (Bob Andrews)
ddpbsd (Dan Parriott)
jubois 
MangyCoyote 
mephesto1337 



Release Notes

	OSSECCON 2019, from the whole team here at OSSEC it was really fantastic meeting everyone at the show, and we look forward to seeing you all again at OSSECCON 2020!
	PCRE2, Jubois made a major update to the IDS foundation in OSSEC 3.3.0 with PCRE2 (https://www.pcre.org/current/doc/html/pcre2.html) library. This is an extremely powerful update to the overall pattern analysis functionaility in OSSEC. In order to build this with the native distribution pcre2 packages (pcre2-devel, etc), you will need to use: export PCRE2_SYSTEM=yes. This adds several new xml tags:
	    - pcre2 (to replace regex)
	    - match_pcre2
	    - program_name_pcre2
	    - prematch_pcre2
	    - srcgeoip_pcre2
	    - dstgeoip_pcre2
	    - srcport_pcre2
	    - dstport_pcre2
	    - user_pcre2
	    - url_pcre2
	    - id_pcre2
	    - status_pcre2
	    - hostname_pcre2
	    - extra_data_pcre2

	Dynamic Decoders, discussed in the "Beyond Security" talk at OSSECCON 2019, this allows for user-defined keys in decoders. These are exposed in JSON output for inclusion with other data analytics tools. This adds a new internal option: analysisd.decoder_order_size  to define the maximum number keys allowed in a single decoder. 


Whats New
	
	(jubois) - PCRE2 regular expression support - PR#1652
	(atomicturtle) - ossec-analysisd, Dynamic decoder support. Original: Vikman Fdez-Castro  - PR#1678
	(ddpbsd) - ossec-execd, Switch "white lists" to "allow lists" - PR#1687 - NARRATE HERE

New Rules / Decoders
	(Bob-Andrews) - rootcheck, update  for NullSessionShares - PR#1669
	(Bob-Andrews) - topleveldomainrules.xml, Shady TLD web traffic detection - PR#1671
	(Bob-Andrews) - last_rootlogin_rules.xml, Sensitive login detection - PR#1671
	(Bob-Andrews) - unbound_rules.xml, added rule for maybe critical TLD request - PR#1672
	(Bob-Andrews) - rootcheck, Deleted repeating rules - PR#1674
	(ddpbsd) - Update info links in Windows rules - PR#1675
	(aquerubin) - Added decoder for pam_succeed_if - PR#1684


General
	(MangyCoyote) - ossec-analysisd, support Syslog ISO timestamp events with optional fraction of second - PR#1664
	(ddpbsd) - Fix compilation with PCRE2_SYSTEM=yes - PR#1666
	(aquerubin) - ossec-batch-manager.pl, update regexp for ipv6 addresses - PR#1667
	(mephesto1337) - Fix part of issue#1663, compiling with PCRE2_SYSTEM=yes - PR#1677
	(ddpbsd) - active-response, Fix for issue#1647, log disable-account.sh to the correct location - PR#1683
	(aquerubin) - Copy resolv.conf on build event - PR#1685	
	(almirb) - active-response, Corrected the way active-response logs are generated on windows - PR#1689
	(atomicturtle) - ossec-execd, Expose filename variable in AR add/delete events - PR#1695
	



OSSEC changelog (3.2.0) <scott@atomicorp.com>


Release Maintainers

Dan Parriott
Scott R. Shinn (Atomicorp, Inc.)

Contributors on this release

atomicturtle
Bob-Andrews
ddpbsd
knqyf263
jubois
mig5
mwmahlberg
nhatking16591
pillarsdotnet


Release Notes
	The great JSON-in-ing has begun! New features in this release focus on extending JSON output support to control commands like agent_control, syscheck_control, and rootcheck_control. Additional extensions add support for archives.log in native json format, and improving the alert.json output. This release also also brings some much needed enhancements to ossec-authd to streamline the agent registration experience (thanks nhatking16591!), Bob-Andrews continues on major auditing improvements plus support for Solaris 11. 

	We'd like to thank all the great contributors (named and anonymous!) who continue to improve ossec and support our community. We'd also like to welcome all our new contributors to OSSEC on this release. They have helped us on bug testing, documentation, new features, rules, compliance checks, code and more. There are no small contributions to a project like OSSEC, and we continue to thrive with your support. Special thanks to security researchers A.P. and S.S. for their audit of the ossec project, your work has greatly benefited the community. 

	If you're interested in joining our team, or just interacting with us on slack email us at: invite@ossec.net
	



Whats New

	(atomicturtle) - add ossec-configure to contrib - PR#1559
	(atomicturtle) - add <log_format>audit</log_format> for native audit.log support - PR#1589
	(nhatking16591) - authd, Allow reuse ID and improve search algorithm finding available ID key. Fixes issue#1587, PR#1594
	(ddpbsd) - syscheck, add <no_recurse> option to keep FIM from going down directories. Addresses Issue#1595 - PR#1597
	(atomicturtle) - archives.json, JSON support for archives.log with <logall_json>yes</logall_json> - PR#1596, PR#1601, PR#1608
	(atomicturtle) - agent_control, -j for JSON output - PR#1625
	(atomicturtle) - syscheck/rootchec_control, add -j for JSON output - PR#1626
	(atomicturtle) - manage_agents, add -j for JSON output, -a to add new agent, -a -n add new agent with declared name - PR#1627
	(atomicturtle) - internal_options.conf, remoted.pass_empty_keyfile will toggle if remoted exits on an empty client.keys file - PR#1628 
	(atomicturtle) - manage_agents, add -d modifier to -a (add) to remove an agent pinned to an already declared IP - PR#1632
	(atomicturtle) - manage_agents, add -F <sec> modifier to -a (add), this will delete an agent with the same IP if it has not been seen in -F <secs> - PR#1639
	(atomicturtle) - manage_agents, add -m flag to show the max agent limit - PR#1650


New Rules / Decoders
	(Bob-Andrews) - rootcheck, add Solaris11 CIS checks - PR#1557
	(Bob-Andrews) - rootcheck, add password requirement checks - PR#1558, PR#1562
	(Bob-Andrews) - Kasperskey Endpoint Security rules/decoders - PR#1573
	(Bob-Andrews) - Cowrie / Dionaea Modern Honeypot Network rules/decoders - PR#1574
	(Bob-Andrews) - Dionaea/Cowrie decoder, Changed IPv4 to IPv4/IPv6 - PR#1578
	(Bob-Andrews) - Windows Powershell rules: ms_powershell_rules.xml, add powershell rules - PR#1579
	(jubois) - proftpd decoder: decoder simplification - PR#1657
	(ddpbsd) - nsd rules: nsd_rules.xml, detect zone transfer attempts - PR#1598
	(Bob-Andrews) - Windows Powershell rules: ms_powershell_rules.xml,  dangerous commands/background activity - PR#1646


General
	(mig5) - firewall-drop.sh, modify to support non-bash environments - PR#1572
	(mwmahlberg) - ossec-agent.conf, remove double hyphen in comment. Fixes issue#1582 - PR#1583
	(ddpbsd) - ossec-maild, allow permission changes to make it into email alerts. Fixes issue#1571 - PR#1593
	(ddpbsd) - installation, addresses issue#1570, allow installation as unpriv user - PR#1599
	(atomicturtle) - JSON output, basic json functions for agent_control - PR#1600, PR#1602
	(ddpbsd) - ossec-authd, use IPExist to check for duplicate IP addresses - PR#1603
	(ddpbsd) - general, default to not setting the compiler optimization level - PR#1604
	(ddpbsd) - general, default to showing verbose compiler output - PR#1605
	(atomicturtle) - agent_control, JSON output prep work - PR#1606
	(atomicturtle) - JSON output, adding functions for rootcheck compliance output in JSON - PR#1607
	(atomicturtle) - JSON output, minor optimization - PR#1609
	(atomicturtle) - agent_control, minor fixes for JSON output - PR#1610
	(ddpbsd) - zlib, shifting dependencies to the system zlib - PR#1612
	(ddpbsd) - LUA, disable lua by default, shifting dependencies to the system lua - PR#1613
	(ddpbsd) - security review, coverity fixes - PR#1616
	(atomicturtle) - JSON output, minor update for JSON log dirs/files - PR#1617
	(atomicturtle) - JSON output, fix lf location array from unknown syslog - PR#1618
	(atomicturtle) - manage_agents, bugfix  when generating keys from a file - PR#1619
	(atomicturtle) - ossec-analysisd, increase default memory size from 1024 to 8192 (dcid) - PR#1620
	(ddpbsd) - security review, coverity fixes - PR#1621
	(atomicturtle) - JSON output, adding more groups, and clean up formatting - PR#1622
	(ddpbsd) - security review, coverity fixes for PR#1624 - PR#1629	
	(ddpbsd) - manage_agents, add an error path for being unable to chmod authfile - PR#1629	
	(pillarsdotnet) - active-response, directory traversal fix - PR#1630
	(ddpbsd) - ossec-control, remove author tag from output - PR#1633
	(atomicturtle) - agent management cleanup, rootcheck/syscheck data is removed on a delete event - PR#1634
	(ddpbsd) - json output, add prototype for function/ fixing compile warnings - PR#1636
	(ddpbsd) - json output, cleanup for unused variables - PR#1637
	(ddpbsd) - ossec-maild, remove legacy sms output type - PR#1638
	(ddpbsd) - agent_control, usage output update - PR#1640
	(jubois) - dotests.sh, Improved dotests.sh output - PR#1641
	(jubois) - Correct tests in contrib/logtesting - PR#1645
	(atomicturtle) - ossec-analysisd, fix for analysisd segfault in overwrite rule condition - PR#1649
	(atomicturtle) - ossec-csyslogd, fix for size returned from a tcp syslog event - PR#1653
	(jubois) - fix compilation warnings - PR#1654
	(knqyf263) - ossec-maild, fix for email being sent infinitely - PR#1658


OSSEC changelog (3.1.0) <scott@atomicorp.com>

Release Maintainers

Dan Parriott
Scott R. Shinn (Atomicorp, Inc.)


Release Notes

	Special thanks on this release go out to:
	 davestoddard for an amazingly well thought out, and well documented update to the networking code
	 Bob-Andrews for the largest update to the auditing system in the project history
         phamvoung for resolving some very subtle bugs and high profile issues with the authd daemon

	We'd also like to thank all the other fantastic contributors to the project, whom are referenced in parenthesis in the changelog. We cannot thank you enough!
	
		
	

Whats New
	(davestoddard) Modification to Correct IP Connectivity Issues on BSD Servers PR #1412

New Rules / Decoders
	(Bob-Andrews) - linux_usbdetect_rules.xml, ms1016_usbdetect_rules.xml, ms_firewall_rules.xml
	(Bob-Andrews) - Added ms_ipsec_rules PR #1549
	(Bob-Andrews) - Rootchecks for Debian 7+8, cis_debianlinux7-8_L1_rcl.txt, cis_debianlinux7-8_L2_rcl.txt, cis_win10_enterprise_L1_rcl.txt, cis_win10_enterprise_L2_rcl.txt PR #1531
	(Bob-Andrews) - acsc_office2016_rcl.txt, Added rootcheck PR #1510
	(Bob-Andrews) - added cis_win2016_memberL1_rcl.txt, cis_win2016_memberL2_rcl.txt PR #1496
	(Bob-Andrews) - cis_win2012r2_memberL1_rcl.txt, Added Check Description/Alert PR #1495
	(ddpbsd) - additional sshd decoders PR #1480
	(ddpbsd) - basic support for Dnsmasq PR #1461

General
	(iasdeoupxe) - host-deny.sh: Move duplicate entry check into the add action PR #1554
	(iasdeoupxe) - host-deny.sh: Use consistent indentation PR #1553
	(iasdeoupxe) - host-deny.sh: Remove unnecessary echo for duplicated entry PR #1552
	(Bob-Andrews) - Added new id ranges for linux usb detection rules, ms1016 usb detection rules and ms firewall rules from PR #1543
	(Bob-Andrews) - Corrected IDs to a non user defined range PR #1547 (psad_rules.xml, sysmon_rules.xml, unbound_rules.xml)
	(c0r3dump3d) - Correct and expand spanish translation PR #1541
	(ddpbsd) - Adjust the tests for sysmon rules PR #1548
	(MangyCoyote) - install.sh - case for s-nail patch can't be applied if `mail` is not installed PR #1539
	(atomicturtle) - ossec-authd Fix for foreground flags PR #1538
	(atomicturtle) - ossec-authd Add -f foreground flag support PR #1537
	(featzor) - psad signature match level 6 PR #1517
	(Bob-Andrews) - Corrected rootcheck CIS tests for cis_win2012r2_domainL2_rcl.txt, is_win2012r2_memberL2_rcl.txt, cis_win2016_domainL2_rcl.txt PR #1521
	(franciosi) - Updated README.md, correts small typos PR #1519
	(ddpbsd) - Fix the subject handling. Issue submitted by Michael Starks #1370 PR #1377
	(foygl) - ossec-slack.sh, Fix and clean up output for Slack integration PR #1508
	(ddpbsd) - From issue #1514, a duplicate `_gsid1 == 0` -> `_gsid0 == 0` PR #1515
	(Bob-Andrews) - cis_win2016_domainL1_rcl.txt, Corrected Check - Registry Hive PR #1511
	(ashley-dunn) - Fix "bellow" typos in ossec-[client|local|server].sh files PR #1512
	(ddpbsd) - Fix the log location in the ossec-slack AR script. PR #1422
	(phamvuong) - BUGFIX: remove default value for authpass PR #1464
	(calve) - Bump version definition in defs.h PR #1504
	(ddpbsd) - More coverity fixes PR #1497
	(ddpbsd) - Modify status() to not return 1 when maild is not running PR #1501
	(ddpbsd) - Coverity fixes PR #1490
	(Bob-Andrews) - Moved file to ossec-hids/ src/rootcheck/db/ PR #1493
	(ddpbsd) - Make sure there's room for the full alert id in json alerts PR #1487
	(ddpbsd) - Fix an issue in the nodiff option which could ignore files it isn't supposed to PR #1486
	(ddpbsd) - Hard coded user/group changed to appropriate variables PR #1484
	(ddpbsd) - Add FreeBSD's php.ini location to rootcheck db PR #1483
	(ddpbsd) - Replace hard coded directories with the appropriate variables PR #1482
	(ddpbsd) - When trying to bind to a local address, present the error on failure. PR #1457
	(ddpbsd) - version_bump.sh Quick script to make version bumping easier PR #1532
	(phamvuong)  - Call select() before checking active socket PR #1529
	(stephengroat) - use nicer looking travis build badge PR #1460
	(stevhsu) - Correct lua version variable PR #1459




OSSEC changelog (3.0.0) <scott@atomicorp.com>

Release Maintainers

Dan Parriott
Scott R. Shinn (Atomicorp, Inc.)

Whats New
	SQLite support for syscheck
		PR #1091 - whitelist for files in sqlite DB
		PR #1364 - add some ifdefs for the md5 whitelist database (USE_SQLITE)

	Update cJSON 1.7.0
		PR #1351

	Add Pagerduty Active response
		PR #1302

	OSSEC-authd 

		PR #890 / #873 - Dichotomic search to add agents with authd
		PR #1154 / #1210 - password support
		PR #1161 - avoid IP duplication, time limit agent deletion with duplicate IP, and option for re-using an agent ID
		PR #1190 - Exit handler for authd to delete PID file
		PR #1208 - add cipher configuration support

	zlib update to 1.2.11
		PR #1198

	ossec-agent selinux module
		PR #1193

	windows agent
		PR #1170 - add agent-auth.exe support

	add tcp support for agent communications
		PR #1162

	GeoIP support in rules and events
		PR #840 - Support in alerts
		PR #927 - add geoip support to JSON output analysisd.geoip_jsonout=0
		PR #929 - Modify rule token different_geoip rule to different_srcgeoip
		PR #984 - fix some geoIP bugs
		PR #1108 - decoder fixes

	Slack support
		Bugfix #947 - Escape the '.' in the grep for '.ALERTLAST' #947
		Bugfix #959 - silent curl in ossec-slack

	Decoders filename attribute
		PR #915 - A few fixes, but most importantly the ability to set the filename attribute from a decoder. This will help create automated pipelines for FIM Verification. I currently need to compare FIM events against 1) Puppet, 2) GIT, and 3) RPM. This patch allows FIM events to be intercepted by my custom FIM Verification script, which generates logging events which OSSEC can read and turn back into an event with the filename attribute set.



New Rules / Decoders

PR #1297 / #1335 - update named rules
PR #1324 - Bitcoin wallet scans to suspicious URLs
PR #1356 - Openbsd DHCP rules


General

Bugfix #42 - Add option to use unaltered hashes with Windows syscheck 
Bugfix #210 - Time option in rules is rejecting valid syntax. 
Bugfix #425 - manage_agents unable to access /dev/random due to chroot 
Bugfix #454 - Prevent manage_agents from chrooting in bulk mode
Bugfix #780 - Compile warning (and potential segfault) after merge from calve/do_not_show_diff 
Bugfix #829 - Segmentation fault at logcollector
Bugfix #888 - Pull Request #840 reverts some ipv6 support
Bugfix #869 - ossec-agentd is unable to unmerge files
Bugfix #892 - Contrib tools need to be updated for IPv6. 
Bugfix #911 - "any" is broken after change to sacmp for ipv4 networks #911
Bugfix #913 - logcollector goes into loop when a NULL is in the log
Bugfix #960 - do not attempt to start ossec-maild when it is enabled
Bugfix #961 - fix for open file handle when rotating alerts.json
Bugfix #976 - win32: 2 values in internal_options.conf ignored 
Bugfix #994 - rootcheck, fix for false positive trojaned /bin/grep
Bugfix #998 - IPv6 triggers Rule 1002 
Bugfix #1065 - fix for negating IP/CIDR rules
Bugfix #1084 - fix a double free 
Bugfix #1106 - ossec-remoted, Fix for clang checks, and a potential DOS caused by a warning
Bugfix #1142 - CEF field uniqueness fix
Bugfix #1145 - if getaddrinfo fails with WAI_FAMILY try ipv4
Bugfix #1165 - rpm spec files generate ossec user and group in user space
Bugfix #1180 - Add last events (previous output) to JSON output 
Bugfix #1205 - Avoid EOL conversion of received files in the windows receiver
Bugfix #1227 - Fix for daily reports not being sent
Bugfix #1237 - Custom CFLAGS/CXXFLAGS/LDFLAGS support
Bugfix #1274 - ossec-authd, ipv6 returns an invalid key
Bugfix #1278 - Use getent to check for users/group
Bugfix #1366 - Update to rule ID map
Bugfix #1370 - Bugfix for full subject handling 


 
PR #770 - ossec-dbd, postgresql fixes on the user colume, schema, and not null conditions
PR #778 - syscheck, Selective opening mode to extract file hash #778
PR #792 - Check for a null from malloc
PR #802 - ossec-dbd, allow for longer entries in the system.information column
PR #804 - ossec-dbd, allow for mysql/postgres format changing based on MYSQLDB/POSTGDB
PR #806 - ossec-reportd, report fixes on IP and user fields
PR #808 - Igngore openBSD's random seed
PR #824 - ossec-dbd, fix for mysql/postgres insert condition
PR #839 - JSON output, Add group field to json output
PR #843 - Add support for CZMQ v3
PR #848 - Fixed bug at logcollector that inhibited alerts about file reduction
PR #849 - ossec-maild, Format string security fix 
PR #855 - Fixed memory error on CDB lists management
PR #859 - added utils to rename an agent or change its IP address (rename_agent.sh, renumber_agent.sh)
PR #862 - ossec-analysisd, fixed memory leaks
PR #864 - There is an error when running ossec-logtest to test rules with check_diff, since it doesn't change root directory and tries to create a directory at/queue/diff`.
PR #866 - JSON output, Add timestamp for events
PR #881 - Add debugging output to active repsonse xml config read
PR #883 - Bugfix for agents failing to bind to a specific local IP address and the server is specified by hostname. 
PR #887 - agent status needs to be verified before using agt->lip
PR #893 - Prelude IDS support, Do not use absolute indexes in prelude fields
PR #899 - manage_agents, OSSEC agent IDs can only be numbers but they are treated as strings. Because of this, it's possible to add the agent "00" and "000", or "1" and "00001" at the same time, and they can be confused on extracting keys or on deleting agents.
PR #909 - ossec-logtest, Bugfix for decoders.d/rules.d segfault
PR #910 - Update intcheck_op.c 
PR #912 - update validate_op.c 
PR #918 - ossec-logtest, add -q "quiet" flag support
PR #920 - Bugfixes for OS_IPFound, OS_IPFoundList, OS_IsValidIP. #920
PR #921 - JSON output, This removes the double addition of the 'action' field and adds a few other interesting fields that I need for my analysis in ELK. Most notably, the rule.group is now passed out via the zmq output.
PR #923 - ossec-dbd, fix SQLi in al_data->location
PR #928 - ossec-logtest, add geoip to logtest output
PR #930 - fix memory leak in decode-xml.c
PR #931 - Custom output, fix common realloc mistake in custom_output_search_replace.
PR #934 - Create OSSEC users and group as system members
PR #944 - Don't pass null variables to snprintf. 
PR #950 - Exclude btrfs-Filesystem from searching for hidden files inside directorie
PR #953 - Prevent manage_agents from doing invalid actions on interactive mode
PR #964 -  Csyslogd patch for sending additional FIM event information
PR #991 - set default AR level to 7
PR #1003 - JSON output, bugfix for duplicated group field 
PR #1004 - memory fixes in XML decoding, no-terminated strings, and searchAndReplace()
PR #1016 - bugfix that prevents ossec-control from starting ossec-maild on server
PR #1017 - ossec-remoted, fix for openbsd canary violation
PR #1020 - Allow notify_timeout to be configured server-side. #1020
PR #1021 - Windows Agent, fix for build related issues
PR #1027 -Fx for the "USER_AGENT_CONFIG_PROFILE" preloaded-vars.conf file usage. This fixes that and adds a profile config line if the variable is defined. Very useful for unattended installs or binary installs.
PR #1089 - Retire picviz support
PR #1090 - JSON output, add "id" to the json log
PR #1093 - pf.sh, update support FreeBSD, OpenBSD, and Darwein
PR #1097 - ossec-batch-manager.pl, support "any" IP address
PR #1099 - AR, prevent duplication in hosts.deny
PR #1100 - Windows agent, Open received files in binary mode cause of cr/lf and let hashes match. 
PR #1102 - JSON output, Fix timestamp 
PR #1116 - ossec-remoted, systemd support
PR #1135 - ossec-dbd, UMYSQL_DATABASE_ENABLED does not exist in the tree except this one place.
PR #1137 - Windows agent, administrators group might not be present on non-english installs
PR #1148 - Update for gmake to compile on Solaris 11.2
PR #1149 - Update adduser.sh for Solaris 11.2
PR #1158 - Update shell on ossec-hids-solaris.init Solaris 11.2
PR #1159 - Update Makefile for Solaris
PR #1179 - ossec-dbd, fix readme display IP as string
PR #1235 - spelling fixes 
PR #1238 - fix for edead oop in hash_op.c
PR #1255 - syscheck, update windows syscheck directories
PR #1256 - ossec-dbd, use port for postgresql connections
PR #1257 - rootcheck, make sleep interval configurable (rootcheck.sleep)
PR #1258 - adduser.sh, fix the useradd and groupadd script for openbsd
PR #1262 - agentless ssh.exp, remove the P's entirely to support upper and lower case
PR #1304 - syscheck, Don't display the errno, show the error message 
PR #1307 - Allow alerts.log to be turned off (DOUBLE CHECK, THIS WAS REVERTED)
PR #1322 - rootcheck, mysql/mariadb auditing checks
PR #1336 - Disable warning on OS_PassEmptyKeyfile
PR #1342 - remove execute flag on rules and config files
PR #1343 - Makefile fix ar warning
PR #1344 - add option to exclude lua and use system zlib
PR #1345 - gitignore, Ignore zlib paths 
PR #1347 - Fix compiler warnings: Wall, Wextra 
PR #1374 - Bugfix for AIX building 
PR #1382 - added rootcheck file for apache 2.2/2.4


