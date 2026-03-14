ossec-debian
============

OSSEC is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response.

This directory is the single canonical location for Debian/Ubuntu packaging. The former debian_files/ at the repo root (versioned layout) has been retired; all packaging lives here under contrib/debian-packages/ (ossec-hids and ossec-hids-agent). These files are used to create OSSEC-HIDS packages (updated for 4.0.0). You can find these packages at:

http://www.ossec.net/?page_id=19

or directly at: http://ossec.wazuh.com/repos/apt/

There are two different packages that can be built with these files:

* ossec-hids: Package that includes both the server and the agent.
* ossec-hids-agent: Package that includes just the agent.

Each one of the subdirectories includes:

* Patches
* Debian control files: changelog, compat, control, copyright, lintian-overrides, postinst, postrm, preinst, rules

Build with generate_ossec.sh: -d (prepare source from local tree or download), -u (create/update pbuilder chroots), -b (build). See PBUILDER.md. Config is in pbuilderrc. The script can also upload to a Reprepro repository (-s). For more details on creating Debian packages and an APT repository you can check:

http://santi-bassett.blogspot.com/2014/07/setting-up-apt-repository-with-reprepro.html

Please don't hesitate to contribute (preferably via pull requests) to improve these packages.
