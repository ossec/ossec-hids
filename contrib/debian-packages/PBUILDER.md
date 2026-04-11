# Building with pbuilder

Use **generate_ossec.sh** with the project's **pbuilderrc**. From the repo root:

```bash
contrib/debian-packages/generate_ossec.sh -d    # prepare source (from local tree or download)
contrib/debian-packages/generate_ossec.sh -u    # create/update chroots (requires sudo)
contrib/debian-packages/generate_ossec.sh -b    # build packages (requires sudo)
```

**`-d`** writes to `contrib/debian-packages/build/` only; it never overwrites the packaging dirs (`ossec-hids/`, `ossec-hids-agent/`). When the repo has `src/`, the tarball is built from the local tree. Otherwise it downloads from GitHub or uses `SOURCE_TARBALL`.

Set **codenames** and **architectures** at the top of generate_ossec.sh, or override for one run:

```bash
CODENAMES=noble ARCHITECTURES=amd64 contrib/debian-packages/generate_ossec.sh -d
CODENAMES=noble ARCHITECTURES=amd64 contrib/debian-packages/generate_ossec.sh -u
CODENAMES=noble ARCHITECTURES=amd64 contrib/debian-packages/generate_ossec.sh -b
```

Built packages: after `-b`, `.deb` and `.changes` are in both
- **`contrib/debian-packages/build/result/<codename>-<arch>/`** (e.g. `build/result/noble-amd64/`)
- `/var/cache/pbuilder/<codename>-<arch>/result/<package>/`

## Pbuilder config (pbuilderrc)

Chroots and results go under `/var/cache/pbuilder/`. To create or update a chroot by hand:

```bash
sudo DIST=noble ARCH=amd64 pbuilder create --configfile contrib/debian-packages/pbuilderrc
sudo DIST=noble ARCH=amd64 pbuilder update --configfile contrib/debian-packages/pbuilderrc
```

Supported codenames are in pbuilderrc (e.g. Ubuntu: noble, jammy, focal; Debian: bookworm, trixie, sid).

## From a non-Debian host (e.g. Fedora)

Install pbuilder and debootstrap. The Ubuntu keyring is often provided by the pbuilder package (`/usr/share/keyrings/ubuntu-archive-keyring.gpg`). Then run `-d`, `-u`, `-b` as above with `CODENAMES` and `ARCHITECTURES` set.

If a build fails, the script prints the last 100 lines of the build log to the terminal and to `ossec_packages.log`. Full log: `contrib/debian-packages/build/pdebuild-<package>-<codename>-<arch>.log`.

## Help

```bash
contrib/debian-packages/generate_ossec.sh -h
```

Log: `contrib/debian-packages/ossec_packages.log`.
