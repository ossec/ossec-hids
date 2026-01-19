# Linux OS Detection Update for OSSEC

## Overview
This document describes the changes made to OSSEC's Linux operating system detection to support modern Linux distributions and container environments.

## Changes Made

### 1. Enhanced Linux Distribution Detection (`src/shared/file_op.c`)

#### Added Modern Distribution Detection
- **Location**: `detect_linux_distribution()` function in `src/shared/file_op.c`
- **Primary Method**: `/etc/os-release` parsing (modern standard)
- **Fallback Methods**: Legacy distribution files

#### Supported Distributions

##### **Modern Distributions (via /etc/os-release)**
- **Ubuntu** (20.04, 22.04, 24.04, etc.)
- **Debian** (11, 12, 13, etc.)
- **Red Hat Enterprise Linux** (8, 9, 10, etc.)
- **CentOS** (8, Stream, etc.)
- **Rocky Linux** (8, 9, etc.)
- **AlmaLinux** (8, 9, etc.)
- **Fedora** (35, 36, 37, 38, 39, 40, etc.)
- **SUSE Linux Enterprise Server** (15, 16, etc.)
- **openSUSE** (Leap, Tumbleweed)
- **Alpine Linux** (3.18, 3.19, etc.)
- **Amazon Linux** (2022, 2023, etc.)
- **Oracle Linux** (8, 9, etc.)
- **Any distribution** that follows the `/etc/os-release` standard

##### **Legacy Distributions (via fallback files)**
- **Red Hat Family**: `/etc/redhat-release`
- **Debian Family**: `/etc/debian_version`
- **SUSE Family**: `/etc/SuSE-release`
- **Alpine Linux**: `/etc/alpine-release`
- **Gentoo**: `/etc/gentoo-release`
- **Slackware**: `/etc/slackware-version`

#### Container Environment Detection
- **Location**: `detect_container_environment()` function
- **Supported Environments**:
  - **Docker**: Detects `/.dockerenv` file
  - **Kubernetes**: Detects `/var/run/secrets/kubernetes.io` directory
  - **LXC/LXD**: Parses `/proc/1/environ` for container variables
  - **systemd-nspawn**: Detects `/etc/systemd/nspawn` directory

### 2. Updated `getuname()` Function

#### Enhanced Output Format
The `getuname()` function now provides much more detailed information:

**Before:**
```
Linux myserver 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 - OSSEC v3.6.0
```

**After (with distribution info):**
```
Ubuntu 22.04.3 LTS (Jammy Jellyfish) myserver 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 - OSSEC v3.6.0
```

**After (with container info):**
```
Ubuntu 22.04.3 LTS (Jammy Jellyfish) (Docker) myserver 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 - OSSEC v3.6.0
```

#### Improved Memory Management
- Increased buffer size from 512 to 1024 bytes for longer distribution names
- Proper memory cleanup for distribution and container information
- Fallback to original format if detection fails

### 3. Helper Functions Added

#### `read_line_from_file()`
- Safely reads a single line from a file
- Handles memory allocation and cleanup
- Removes newline characters

#### `get_value_from_key_value()`
- Parses key=value format from `/etc/os-release`
- Handles quoted values properly
- Returns clean values without quotes

#### `detect_linux_distribution()`
- Primary distribution detection logic
- Tries `/etc/os-release` first (modern standard)
- Falls back to legacy files if needed
- Returns human-readable distribution information

#### `detect_container_environment()`
- Detects various container environments
- Checks for container-specific files and directories
- Returns container type if detected

## Benefits

### 1. **Better Server Management**
- **Accurate Distribution Information**: Server administrators can now see exactly which Linux distribution each agent is running
- **Version Awareness**: Specific version numbers help with compatibility and support
- **Container Visibility**: Container environments are clearly identified

### 2. **Enhanced Security Monitoring**
- **Distribution-Specific Rules**: Can apply different security rules based on distribution
- **Container Security**: Special monitoring for containerized environments
- **Compliance**: Better tracking for compliance requirements

### 3. **Improved Troubleshooting**
- **Quick Identification**: Easy to identify system types from logs
- **Version-Specific Issues**: Can correlate issues with specific distribution versions
- **Container Debugging**: Clear identification of container vs. bare metal systems

## Examples

### Distribution Detection Examples

**Ubuntu 22.04:**
```
Ubuntu 22.04.3 LTS (Jammy Jellyfish) myserver 5.15.0-88-generic x86_64 - OSSEC v3.6.0
```

**RHEL 9:**
```
Red Hat Enterprise Linux 9.3 (Plow) myserver 5.14.0-284.11.1.el9_2.x86_64 x86_64 - OSSEC v3.6.0
```

**Alpine Linux:**
```
Alpine Linux 3.18.4 myserver 6.1.0-13-alpine x86_64 - OSSEC v3.6.0
```

**Docker Container:**
```
Ubuntu 22.04.3 LTS (Jammy Jellyfish) (Docker) myserver 5.15.0-88-generic x86_64 - OSSEC v3.6.0
```

**Kubernetes Pod:**
```
Red Hat Enterprise Linux 9.3 (Plow) (Kubernetes) myserver 5.14.0-284.11.1.el9_2.x86_64 x86_64 - OSSEC v3.6.0
```

## Backward Compatibility

### 1. **Non-Linux Systems**
- All non-Linux systems continue to use the original format
- No changes to BSD, macOS, Solaris, etc. detection

### 2. **Fallback Support**
- If distribution detection fails, falls back to original format
- Legacy distribution files are still supported
- No breaking changes to existing functionality

### 3. **Memory Safety**
- Proper memory allocation and cleanup
- No memory leaks introduced
- Safe handling of file operations

## Testing Recommendations

### 1. **Distribution Testing**
Test on various distributions:
- Ubuntu 20.04, 22.04, 24.04
- RHEL 8, 9, 10
- CentOS 8, Stream
- Debian 11, 12
- Alpine Linux 3.18, 3.19
- SUSE SLES 15, 16

### 2. **Container Testing**
Test in various container environments:
- Docker containers
- Kubernetes pods
- LXC/LXD containers
- systemd-nspawn containers

### 3. **Edge Cases**
Test edge cases:
- Systems without `/etc/os-release`
- Systems with malformed distribution files
- Systems with very long distribution names
- Memory-constrained environments

## Future Enhancements

### 1. **Cloud Provider Detection**
- AWS EC2 metadata detection
- Azure instance metadata detection
- Google Cloud metadata detection

### 2. **Systemd Version Detection**
- Include systemd version in output
- Help identify systemd-based vs. init-based systems

### 3. **Kernel Module Detection**
- Detect security modules (SELinux, AppArmor)
- Include in system information

### 4. **Hardware Information**
- CPU architecture details
- Memory information
- Storage information

## Conclusion

These enhancements significantly improve OSSEC's ability to identify and report Linux system information, making it easier for administrators to manage and secure their environments. The changes maintain full backward compatibility while adding modern distribution detection capabilities. 