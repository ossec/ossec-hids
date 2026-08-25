## OSSEC SELinux module

Optional SELinux policy for confining the OSSEC agent under
`/var/ossec`. Server/manager confinement is not covered yet (see #1948).

### Quick fix for logrotate AVCs (#1948)

If SELinux blocks logrotate on `/var/ossec/logs/*` and you are **not**
using this module, label the logs like other system logs:

```bash
semanage fcontext -a -t var_log_t '/var/ossec/logs(/.*)?'
restorecon -Rv /var/ossec/logs
```

Do **not** use `logrotate_exec_t` / `logrotate_tmp_t` / similar — those
are for logrotate's own files, not for application logs.

RPM packages apply the `var_log_t` mapping automatically when this
module is not loaded.

### Installing this module

Requires `checkpolicy`, `policycoreutils`, and `selinux-policy-devel`
(package names vary by distro). On Fedora/RHEL also install
`policycoreutils-python-utils` for `semanage`.

```bash
cd contrib/selinux/ossec_agent
make
semodule -i ossec_agent.pp
# or: semodule -i ../ossec_agent.pp.bz2
restorecon -Rv /var/ossec
systemctl restart ossec   # or ossec-hids / ossec-hids-agent
ps -eZ | grep ossec
```

If `semodule -i ossec_agent.pp.bz2` fails looking for
`/usr/libexec/selinux/hll/bz2`, decompress first:

```bash
bunzip2 -k ossec_agent.pp.bz2
semodule -i ossec_agent.pp
```

After the module is installed, logs use `ossec_log_t` (see `.fc`).
Remove any conflicting local mapping first:

```bash
semanage fcontext -d '/var/ossec/logs(/.*)?' 2>/dev/null || true
restorecon -Rv /var/ossec/logs
```

Custom install prefix: adjust paths in `ossec_agent.fc` and re-run
`make` / `restorecon`.

### Building

```bash
cd contrib/selinux/ossec_agent && make
```

Ship/update the compressed module from the repo root with
`make -C contrib/selinux/ossec_agent pp-bz2`.

### Bug reports & contribution

Original author: ivan.agarkov@gmail.com
