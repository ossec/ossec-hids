# Windows OS Detection Update for OSSEC

## Overview
This document describes the changes made to OSSEC's Windows operating system detection to support modern Windows versions including Windows 10, Windows 11, and Windows Server 2016/2019/2022.

## Changes Made

### 1. Updated Windows Version Detection (`src/shared/file_op.c`)

#### Added Windows 10/11 Detection
- **Location**: `getuname()` function in `src/shared/file_op.c`
- **New Detection Logic**: Added support for Windows major version 10
- **Build Number Detection**:
  - Windows 11: Build number >= 22000
  - Windows 10: Build number < 22000 (but >= 10240)
  - Windows Server 2022: Build number >= 20348
  - Windows Server 2019: Build number >= 17763 (but < 20348)
  - Windows Server 2016: Build number < 17763

#### Updated `checkVista()` Function
- **Location**: `checkVista()` function in `src/shared/file_op.c`
- **Added String Matching**: Now includes detection for:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022

### 2. Added Missing Windows Constants and Types

#### Windows Includes
Added necessary Windows headers:
```c
#include <windows.h>
#include <winbase.h>
#include <winreg.h>
#include <sysinfoapi.h>
#include <versionhelpers.h>
```

#### Windows Constants
Added missing Windows constants:
- `MOVEFILE_REPLACE_EXISTING`
- `MOVEFILE_WRITE_THROUGH`

#### Windows Types
Added type definitions for Windows-specific types:
- `DWORD`
- `HANDLE`
- `PACL`
- `PSECURITY_DESCRIPTOR`
- `EXPLICIT_ACCESS`
- `SECURITY_ATTRIBUTES`
- `PSID`

## Windows Version Detection Matrix

| Windows Version | Major Version | Minor Version | Build Number Range | Detection String |
|-----------------|---------------|---------------|-------------------|------------------|
| Windows 10 | 10 | 0 | 10240-21999 | "Microsoft Windows 10" |
| Windows 11 | 10 | 0 | 22000+ | "Microsoft Windows 11" |
| Windows Server 2016 | 10 | 0 | 14393-17762 | "Microsoft Windows Server 2016" |
| Windows Server 2019 | 10 | 0 | 17763-20347 | "Microsoft Windows Server 2019" |
| Windows Server 2022 | 10 | 0 | 20348+ | "Microsoft Windows Server 2022" |

## Product Edition Detection

The updated code maintains support for all existing Windows product editions:
- Home Basic/Home Premium
- Professional
- Enterprise
- Ultimate
- Business
- Starter
- Datacenter Server (full and core)
- Standard Server (full and core)
- Web Server
- Storage Server (various editions)
- Small Business Server
- Medium Business Server
- Cluster Server
- And many more specialized editions

## Example Output

### Windows 10 Professional
```
Microsoft Windows 10 Professional (Build 19044) - OSSEC v3.6.0
```

### Windows 11 Enterprise
```
Microsoft Windows 11 Enterprise Edition (Build 22621) - OSSEC v3.6.0
```

### Windows Server 2022 Datacenter
```
Microsoft Windows Server 2022 Datacenter Edition (full) (Build 20348) - OSSEC v3.6.0
```

## Backward Compatibility

- All existing Windows versions (Windows 2000 through Windows 8.1/Server 2012 R2) continue to be detected as before
- The `checkVista()` function now correctly identifies Windows 10/11 as "Vista or newer" systems
- No changes to the detection logic for non-Windows operating systems

## Testing Recommendations

1. **Test on Windows 10 systems** with different editions (Home, Pro, Enterprise)
2. **Test on Windows 11 systems** with different editions
3. **Test on Windows Server 2016/2019/2022** systems
4. **Verify backward compatibility** with older Windows versions
5. **Test the `checkVista()` function** to ensure it correctly identifies new Windows versions

## Build Requirements

When compiling for Windows:
- Windows SDK 10.0.17763.0 or later (for Windows 10/11 support)
- Visual Studio 2017 or later (for C99 support)
- Windows 10 SDK headers and libraries

## Notes

- The detection relies on the Windows API `GetVersionEx()` and `GetProductInfo()` functions
- Build numbers are used to distinguish between Windows 10 and Windows 11 (both use major version 10)
- Server versions are distinguished by build number ranges
- The detection includes service pack and build number information in the output 