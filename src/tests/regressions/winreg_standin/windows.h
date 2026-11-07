/* Stand-in for the Windows SDK header: just enough to compile the unmodified WIN32 syscheck sources on Linux.
 * Names, types, constants and prototypes are the SDK's; windows_stand_in.c implements the functions. */
#ifndef STAND_IN_WINDOWS_H
#define STAND_IN_WINDOWS_H

#include <stddef.h>
#include <stdint.h>

#define __int32 int
#define __cdecl
#define __stdcall
#define __declspec(x)
#define WINAPI

/* headers/shared.h typedefs these itself when WIN32 is defined; keep them off the glibc names */
#define uid_t win32_uid_t
#define gid_t win32_gid_t
#define socklen_t win32_socklen_t

typedef uint8_t BYTE, *LPBYTE;
typedef uint32_t DWORD, *LPDWORD;
typedef int32_t LONG;
typedef int BOOL, *PBOOL;
typedef char TCHAR, *LPSTR;                 /* the agent is built without -DUNICODE */
typedef const char *LPCSTR;
typedef void *LPVOID, *HANDLE, *HMODULE, *HKEY;
typedef HKEY *PHKEY;
typedef DWORD REGSAM;
typedef intptr_t (*FARPROC)(void);
typedef DWORD (*LPTHREAD_START_ROUTINE)(LPVOID);

#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define INFINITE 0xFFFFFFFF

#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_INVALID_PARAMETER 87
#define ERROR_MORE_DATA 234
#define ERROR_NO_MORE_ITEMS 259

#define HKEY_CLASSES_ROOT   ((HKEY)(uintptr_t)0x80000000)
#define HKEY_LOCAL_MACHINE  ((HKEY)(uintptr_t)0x80000002)
#define HKEY_USERS          ((HKEY)(uintptr_t)0x80000003)
#define HKEY_CURRENT_CONFIG ((HKEY)(uintptr_t)0x80000005)

#define KEY_READ 0x20019
#define KEY_WRITE 0x20006
#define KEY_WOW64_64KEY 0x0100
#define KEY_WOW64_32KEY 0x0200

#define REG_SZ 1
#define REG_EXPAND_SZ 2
#define REG_DWORD 4
#define REG_MULTI_SZ 7

LONG RegOpenKeyExA(HKEY key, LPCSTR subkey, DWORD options, REGSAM access, PHKEY result);
LONG RegCreateKeyExA(HKEY key, LPCSTR subkey, DWORD reserved, LPSTR class_name, DWORD options, REGSAM access,
                     LPVOID security_attributes, PHKEY result, LPDWORD disposition);
LONG RegQueryInfoKeyA(HKEY key, LPSTR class_name, LPDWORD class_size, LPDWORD reserved, LPDWORD subkeys,
                      LPDWORD max_subkey_len, LPDWORD max_class_len, LPDWORD values, LPDWORD max_value_name_len,
                      LPDWORD max_value_len, LPDWORD security_descriptor, LPVOID last_write_time);
LONG RegEnumKeyExA(HKEY key, DWORD index, LPSTR name, LPDWORD name_size, LPDWORD reserved, LPSTR class_name,
                   LPDWORD class_size, LPVOID last_write_time);
LONG RegEnumValueA(HKEY key, DWORD index, LPSTR name, LPDWORD name_size, LPDWORD reserved, LPDWORD type,
                   LPBYTE data, LPDWORD data_size);
LONG RegSetValueExA(HKEY key, LPCSTR name, DWORD reserved, DWORD type, const BYTE *data, DWORD data_size);
LONG RegCloseKey(HKEY key);

#define RegOpenKeyEx RegOpenKeyExA
#define RegCreateKeyEx RegCreateKeyExA
#define RegQueryInfoKey RegQueryInfoKeyA
#define RegEnumKeyEx RegEnumKeyExA
#define RegEnumValue RegEnumValueA
#define RegSetValueEx RegSetValueExA

HMODULE GetModuleHandleA(LPCSTR module);
FARPROC GetProcAddress(HMODULE module, LPCSTR name);
HANDLE GetCurrentProcess(void);
DWORD ExpandEnvironmentStringsA(LPCSTR source, LPSTR destination, DWORD size);
void Sleep(DWORD milliseconds);
HANDLE CreateThread(LPVOID security_attributes, size_t stack_size, LPTHREAD_START_ROUTINE start, LPVOID parameter,
                    DWORD flags, LPDWORD thread_id);
DWORD WaitForSingleObject(HANDLE handle, DWORD milliseconds);

#define GetModuleHandle GetModuleHandleA
#define ExpandEnvironmentStrings ExpandEnvironmentStringsA

#endif
