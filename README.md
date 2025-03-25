# Windows System Management Tools (Standalone)

## Introduction

- This repository contains some Windows system management tools.
  - [ec.cpp](#eccpp)
  - [privilege.cpp](#privilegecpp)
  - [resource.cpp](#resourcecpp)
  - [statpp.cpp](#statppcpp)
  - [statreg.cpp](#statregcpp)
  - [Microsoft.PowerShell_profile.ps1](#microsoftpowershell_profileps1)
  - [sqlite3.js](#sqlite3js)
  - [WinRAR-keygen.py](#winrar-keygenpy)
- These tools are standalone. Each tool is a single source file, which relies on few dependencies. It is easy to build and run them independently.
- These tools may only work on Windows except `sqlite3.js`. `Microsoft.PowerShell_profile.ps1` and `WinRAR-keygen.py` may also run on other platforms, but that makes no sense.
- All the commands specified in this document are PowerShell commands. For the C++ tools, you need to open a Developer Powershell for VS 2022 to set up the environment for compilation. The executable files of the C++ tools should be placed in a directory in `$env:Path`.
- The C++ tools are written in C++26, and rely on Windows SDK/WDK. It is recommended to use the latest version of MSVC to compile them. You might also use Clang with MSVC toolchain. GCC (MinGW) is not recommended for the following reasons:
  - `Formatting Ranges` is still not supported by GCC 15. You have to implement it yourself.
  - `std::filesystem::file_time_type` is implementation-defined. GCC uses the POSIX file time type, whose resolution is 1ns and epoch is `2174-01-01 00:00:00.000000000 UTC`. You have to implement a custom file time type, whose resolution is 100ns and epoch is `1601-01-01 00:00:00.0000000 UTC`.
  - GCC requires extra `typename` disambiguators for dependent names in templates. For example, the `FileTime<IsConst>::TimePoint(file_time)` at line 129 of `statpp.cpp` and line 130 of `statreg.cpp` should be `(typename FileTime<IsConst>::TimePoint)(file_time)`.
  - The WDK in MinGW GCC has some compatibility issues. For example, `<GCC root>\x86_64-w64-mingw32\include\ddk\wdm.h` has two extraneous function definitions (`InterlockedBitTestAndSet` and `InterlockedBitTestAndReset`), which would cause compilation errors (`redeclared inline without 'gnu_inline' attribute`). You have to remove them manually.

## ec.cpp

### Description

- This tool converts error codes to human-readable error messages.

### Usage

```
Usage: ec <error code>
Error code: <dec>|0x<hex>|0<oct>
```

- The error code can be specified in signed/unsigned decimal, hexadecimal or octal format.
- The output is three string representations of the error code.
  - `generic`: The error code is treated as `errno`.
  - `system`: The error code is treated as a system error code.
  - `NTSTATUS`: The error code is treated as `NTSTATUS`. The error message is loaded from `ntdll.dll`.

### Examples

```
PS > ec 2
error code: 2 | 2 | 0x00000002 | 02
generic : "no such file or directory"
system  : "系统找不到指定的文件。"
NTSTATUS: "STATUS_WAIT_2\r\n"

PS > ec 0xc0000005
error code: -1073741819 | 3221225477 | 0xc0000005 | 030000000005
generic : "unknown error"
system  : "unknown error"
NTSTATUS: "0xp 指令引用了 0xp 内存。该内存不能为 s。\r\n"
```

### Build

- Command: `cl /O2 /EHsc /std:c++latest /W4 /sdl /DUNICODE ec.cpp /utf-8`
- Compiler Support:
  |Compiler|Minimum Version|Required Options|
  |-|-|-|
  |cl (MSVC)|19.43|`/EHsc /std:c++latest`|
  |g++ (MinGW)|14|`-std=c++26 -lstdc++exp`|
  |clang++ (MSVC)|17 (with MSVC toolchain)|`-std=c++26 --target=x86_64-pc-windows-msvc`|

## privilege.cpp

### Description

- This tool enables all the privileges of the current user.
- If the user is (impersonating) an administrator, this tool will enable privileges like `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeSecurityPrivilege`, etc. As a result, the user can bypass all ACL checks and access any file/directory/registry key.
- Files under `C:\Program Files\WindowsApps` have [`SYSTEM_PROCESS_TRUST_LABEL_ACE`](https://learn.microsoft.com/en-us/archive/blogs/winsdk/why-cant-i-restore-files-even-when-i-have-backuprestore-privileges-enabled) in their SACLs, which will result in `ERROR_ACCESS_DENIED` when trying to:
  - write data/add file
  - append data/add subdirectory
  - write extended attributes
- This tool **cannot** bypass such restrictions. A workaround is to replace the file on the next boot.

  - Copy the file to another directory **on the same volume**.

    ```
    PS > cp 'C:\Program Files\WindowsApps\<dir>\<file>' Temp:\
    ```

  - Modify the file in the new directory.
  - Use `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT` and `MOVEFILE_REPLACE_EXISTING` flags to replace the original file on the next boot.

    ```cpp
    MoveFileEx(
    	TEXT("C:\\Users\\<user>\\AppData\\Local\\Temp\\<file>"),
    	TEXT("C:\\Program Files\\WindowsApps\\<dir>\\<file>"),
    	MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
    ```

  - Reboot the system.

### Usage

```
Usage:
(1)  privilege read <infile> <outfile>
(2)  privilege write <infile> <outfile>
(3)  privilege list <directory>
(4)  privilege mkdir <directory>
(5)  privilege remove <file>
(6)  privilege move <old path> <new path>
(7)  privilege getkv <registry>
(8)  privilege setkv <registry> <name> <type> [<byte> ...]
     <type>: ["NONE", "SZ", "EXPAND_SZ", "BINARY", "DWORD", "DWORD_BIG_ENDIAN", "LINK", "MULTI_SZ", "QWORD"]
     <byte>: 00-ff
(9)  privilege delkv <registry> <name>
(10) privilege listkey <registry>
(11) privilege delkey <registry>
(12) privilege renkey <registry> <new name>
(13) privilege getfacl|getkacl <file|registry>
(14) privilege setf(i)acl|setk(i)acl <file|registry> <sddl>
```

- `<registry>` can be specified in the following formats:
  - `HKCR\...`, `HKCU\...`, `HKLM\...`, `HKU\...`
  - `HKCR:\...`, `HKCU:\...`, `HKLM:\...`, `HKU:\...`
  - `HKEY_CLASSES_ROOT\...`, `HKEY_CURRENT_USER\...`, `HKEY_LOCAL_MACHINE\...`, `HKEY_USERS\...`
  - `Registry::HKEY_CLASSES_ROOT\...`, `Registry::HKEY_CURRENT_USER\...`, `Registry::HKEY_LOCAL_MACHINE\...`, `Registry::HKEY_USERS\...`
- If `<registry>` is a symbolic link, it will not be followed.
- The format of `<sddl>` is described in the [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format).

### Examples

- `privilege read <infile> <outfile>`: Read the content of `<infile>` and write it to `<outfile>`. Bypass the ACLs of `<infile>`.
- `privilege write <infile> <outfile>`: Read the content of `<infile>` and write it to `<outfile>`. Bypass the ACLs of `<outfile>` and its parent directory. `<outfile>` will be created if it does not exist, or overwritten if it exists, but its parent directory must exist.
- `privilege list <directory>`: List the files in `<directory>`. Bypass the ACLs of `<directory>`.
- `privilege mkdir <directory>`: Create `<directory>` recursively. Bypass the ACLs of `<directory>` and its ancestors.
- `privilege remove <file>`: Remove `<file>` recursively. Bypass the ACLs of `<file>` and its descendants.
- `privilege move <old path> <new path>`: Move `<old path>` to `<new path>`. Bypass the ACLs of `<old path>`, `<new path>` and their parent directories. `<old path>` and `<new path>` should be the same type (regular file/directory).
- `privilege getkv <registry>`: Query the properties of `<registry>`. Bypass the ACLs of `<registry>`.
- `privilege setkv <registry> <name> <type> [<byte> ...]`: Add/Update a property of `<registry>`, whose name is `<name>`, type is `<type>`, and value is `<byte>`s. Bypass the ACLs of `<registry>` and its ancestors. If `<registry>` does not exist, it will be created recursively. The `<byte>`s should be zero or more bytes in the range `00-ff`. The value format of each `<type>` is described in the [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types).

  ```
  PS > privilege setkv HKCU:\Test '' SZ 61 00 62 00 63 00 00 00 # set the value of "(Default)" to "abc" (REG_SZ)

  PS > privilege setkv HKCU:\Test TestDWORD DWORD 04 03 02 01 # set the value of "TestDWORD" to 0x01020304 (REG_DWORD)

  PS > privilege setkv HKLM:\SYSTEM\SecondaryControlSet\ SymbolicLinkValue LINK 5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 30 00 30 00 32 00 # create a symbolic link for "\Registry\Machine\SYSTEM\ControlSet002", or update the target of an existing symbolic link
  ```

- `privilege delkv <registry> <name>`: Delete a property of `<registry>`, whose name is `<name>`. Bypass the ACLs of `<registry>`.
- `privilege listkey <registry>`: List the subkeys of `<registry>`. Bypass the ACLs of `<registry>`.
- `privilege delkey <registry>`: Delete `<registry>`. The registry key must not have subkeys. Due to the limitations of Windows SDK APIs, this operation requires `DELETE` access to the registry key to be deleted. You might use the [`statreg`](#statregcpp) tool instead, which uses WDK APIs and has no such restrictions.
- `privilege renkey <registry> <new name>`: Rename `<registry>` to `<new name>`. Due to the limitations of Windows SDK APIs, this operation requires `KEY_WRITE` and `DELETE` access to the registry key, and `KEY_CREATE_SUB_KEY` access to its parent key.
- `privilege getfacl|getkacl <file|registry>`: Get the owner/group/DACL/SACL of `<file>` or `<registry>`. Bypass the ACLs of `<file>` or `<registry>`. To get the ACL of a registry key, this tool first tries the new API `GetSecurityInfo`, which requires `READ_CONTROL` access if the user is not the owner of the registry key. If `GetSecurityInfo` returns `ERROR_ACCESS_DENIED`, this tool will try the old API `RegGetKeySecurity`, which can bypass this restriction.
- `privilege setf(i)acl|setk(i)acl <file|registry> <sddl>`: Set the owner/group/DACL/SACL of `<file>` or `<registry>` to `<sddl>`. Bypass the ACLs of `<file>` or `<registry>`. `setfiacl` and `setkiacl` will also inherit ACEs from the parent directory or parent key. To set the ACL of a registry key, this tool first tries the new API `SetSecurityInfo`, which requires `WRITE_DAC` access if the user is not the owner of the registry key. If `SetSecurityInfo` returns `ERROR_ACCESS_DENIED`, this tool will try the old API `RegSetKeySecurity`, which can bypass this restriction. Pay attention that `RegSetKeySecurity` cannot inherit/propagate ACEs automatically.

  ```
  PS > privilege setfacl file 'O:BAG:BAD:' # set the owner to "BUILTIN\Administrators", group to "BUILTIN\Administrators", DACL to empty (nobody has access), SACL to null (no auditing)

  PS > privilege setkiacl HKCU:\Test 'O:SYG:SYD:(A;OICI;KA;;;SY)S:(AU;OICI;KR;;;WD)' # set the owner to "NT AUTHORITY\SYSTEM", group to "NT AUTHORITY\SYSTEM", DACL to "Grant full access to SYSTEM", SACL to "Audit read access from Everyone"; if `SetSecurityInfo` succeeds, the registry key will also inherit ACEs from its parent key, and propagate ACEs to its subkeys; otherwise, `RegSetKeySecurity` will be called instead, which cannot inherit/propagate ACEs automatically
  ```

### Build

- Command: `cl /O2 /EHsc /std:c++latest /W4 /sdl /DUNICODE privilege.cpp advapi32.lib /utf-8`
- Compiler Support:
  |Compiler|Minimum Version|Required Options|
  |-|-|-|
  |cl (MSVC)|19.43|`/EHsc /std:c++latest (/link) advapi32.lib`|
  |g++ (MinGW)|14 (`Formatting Ranges` not supported)|`-std=c++26 -lstdc++exp`|
  |clang++ (MSVC)|17 (with MSVC toolchain)|`-std=c++26 -ladvapi32 --target=x86_64-pc-windows-msvc`|

## resource.cpp

### Description

- This tool lists/modifies the resources of a PE file (`.exe`, `.dll`, `.sys`, etc.).
- A typical use case is to copy icons from one PE file to another.

### Usage

```
Usage:
(1) resource list <module> [<type> #all|<name>[,<name>...] ...]
(2) resource update|replace <destination module> <source module> [<type> #all|<name>[,<name>...] ...]
(3) resource delete <module> [<type> #all|<name>[,<name>...] ...]
(4) resource dump <module> <dump file> <type> <name>
(5) resource load <module> <dump file> <type> <name>
<type>: ["PLUGPLAY", "GROUP_CURSOR", "CURSOR", "FONT", "DLGINCLUDE", "GROUP_ICON", "ICON", "MENU", "BITMAP", "DIALOG", "STRING", "FONTDIR", "ACCELERATOR", "RCDATA", "MESSAGETABLE", "VERSION", "VXD", "ANICURSOR", "HTML", "ANIICON", "MANIFEST"]
<name>: #<number>|<string>
```

- `<module>`: The path to a PE file.
- `<type> #all|<name>[,<name>...] ...`: `<type>` is the type of one or more resources. `#all` means all resources of the specified type. `<name>` can be a number (e.g. `#1`, `#2`) or a string (e.g. `IDI_ICON1`). You can specify multiple names separated by commas (e.g. `#1,IDI_ICON1,#2`). There should be no spaces around the commas. You can specify multiple types with their names (e.g. `ICON '#1,IDI_ICON1,#2' VERSION '#all'`). The resource types are described in the [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types).
- `<dump file>`: The path to a file with the raw bytes of a resource. There must be only one resource in the file.

### Examples

```
PS > resource list 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' GROUP_ICON 'IDR_MAINFRAME' ICON '#1,#2,#3,#4,#5,#6,#7,#8' VERSION '#all' # list the resources of msedge.exe: GROUP_ICON resource "IDR_MAINFRAME"; ICON resources #1-#8; all VERSION resources
[GROUP_ICON]
IDR_MAINFRAME: <8 icon(s)>
[1] <28625 byte(s)> (0x0, 0 color(s), 32 bit(s), 1 plane(s))
[2] <16936 byte(s)> (64x64, 0 color(s), 32 bit(s), 1 plane(s))
[3] <9640 byte(s)> (48x48, 0 color(s), 32 bit(s), 1 plane(s))
[4] <6760 byte(s)> (40x40, 0 color(s), 32 bit(s), 1 plane(s))
[5] <4264 byte(s)> (32x32, 0 color(s), 32 bit(s), 1 plane(s))
[6] <2440 byte(s)> (24x24, 0 color(s), 32 bit(s), 1 plane(s))
[7] <1720 byte(s)> (20x20, 0 color(s), 32 bit(s), 1 plane(s))
[8] <1128 byte(s)> (16x16, 0 color(s), 32 bit(s), 1 plane(s))
[ICON]
#1: <28625 byte(s)>
#2: <16936 byte(s)>
#3: <9640 byte(s)>
#4: <6760 byte(s)>
#5: <4264 byte(s)>
#6: <2440 byte(s)>
#7: <1720 byte(s)>
#8: <1128 byte(s)>
[VERSION]
#1: <1084 byte(s)>

PS > resource update test.exe 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' GROUP_ICON 'IDR_MAINFRAME' ICON '#1,#2,#3,#4,#5,#6,#7,#8' VERSION '#all' # update the resources of test.exe with the resources of msedge.exe: GROUP_ICON resource "IDR_MAINFRAME"; ICON resources #1-#8; all VERSION resources (the existing resources will be preserved/updated)

PS > resource replace test.exe 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' GROUP_ICON 'IDR_MAINFRAME' ICON '#1,#2,#3,#4,#5,#6,#7,#8' VERSION '#all' # replace the resources of test.exe with the resources of msedge.exe: GROUP_ICON resource "IDR_MAINFRAME"; ICON resources #1-#8; all VERSION resources (the existing resources will be deleted)

PS > resource delete test.exe MANIFEST '#all' # delete the resources of test.exe: all MANIFEST resources

PS > resource dump test.exe test.exe.manifest MANIFEST '#1' # dump the resources of test.exe to test.exe.manifest: all MANIFEST resources (equivalent to: mt -inputresource:test.exe;#1 -out:test.exe.manifest)

PS > resource load test.exe test.exe.manifest MANIFEST '#1' # load the resources of test.exe from test.exe.manifest: all MANIFEST resources (equivalent to: mt -manifest test.exe.manifest -outputresource:test.exe;#1)
```

### Build

- Command: `cl /O2 /EHsc /std:c++latest /W4 /sdl /DUNICODE resource.cpp /utf-8`
- Compiler Support:
  |Compiler|Minimum Version|Required Options|
  |-|-|-|
  |cl (MSVC)|19.42|`/EHsc /std:c++latest`|
  |g++ (MinGW)|14 (`Formatting Ranges` not supported)|`-std=c++26 -lstdc++exp`|
  |clang++ (MSVC)|17 (with MSVC toolchain)|`-std=c++26 --target=x86_64-pc-windows-msvc`|

## statpp.cpp

### Description

- This tool gets/sets the attributes/timestamps of a local/remote file/directory.
- File attributes are described in the [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants).
- File timestamps include:
  - LastAccessTime/atime
  - LastWriteTime/mtime
  - ChangeTime/ctime
  - CreationTime/crtime
- Similar to [`privilege.cpp`](#privilegecpp), this tool can bypass all ACL checks.

### Usage

```
Usage: statpp.exe <file> [<field> <value>]
field: attrs, atime, mtime, ctime, crtime
attrs: "+attr1,-attr2,..." ["READONLY", "HIDDEN", "TEMPORARY", "VIRTUAL", "SYSTEM", "SPARSE_FILE", "DIRECTORY", "ARCHIVE", "ENCRYPTED", "DEVICE", "NORMAL", "REPARSE_POINT", "COMPRESSED", "OFFLINE", "NOT_CONTENT_INDEXED", "INTEGRITY_STREAM", "NO_SCRUB_DATA", "EA", "PINNED", "UNPINNED", "RECALL_ON_OPEN", "RECALL_ON_DATA_ACCESS"]
time : "%F %T %z" (yyyy-mm-dd HH:MM:SS.SSSSSSS ±zzzz)
```

- `<file>`: The path to a local/remote file/directory/pipe. It can be specified as either an NT path or a Win32 path.
  - NT path
    - local: `\Device\HarddiskVolume<number>\<path>`, `\DosDevices\<drive>:\<path>`, `\Global??\<drive>:\<path>`, `\??\<drive>:\<path>`, `\??\PIPE\<name>`
    - remote: `\??\UNC\<server>\<drive>$\<path>` (typically Windows), `\??\UNC\<server>\<path>` (typically Linux)
  - Win32 path
    - absolute: `\\?\<drive>:\<path>`, `\\.\PIPE\<name>`, `<drive>:\<path>`, `\<path>`
    - relative
    - remote: `\\<server>\<drive>$\<path>` (typically Windows), `\\<server>\<path>` (typically Linux)
- If `<file>` is a reparse point (e.g. symbolic link, junction, app execution alias, etc.), it will not be followed.
- `<field> <value>`: If specified, this tool will set the value of the specified field. Otherwise, this tool will get the values of all fields.
- `attrs`: The attributes to set. `+` means to add the attribute, `-` means to remove the attribute. You can specify multiple operations separated by commas.
- `time`: The timestamp to set. The format `"%F %T %z"` is described in the [cppreference](https://en.cppreference.com/w/cpp/chrono/file_clock/formatter).

### Examples

```
PS > statpp C:\test
\??\C:\test
attrs : ["ARCHIVE", "READONLY"]
atime : 2025-01-02 03:04:05.6789012 -0600 (GMT-6)
mtime : 2025-01-02 03:04:05.6789012 -0600 (GMT-6)
ctime : 2025-01-02 03:04:05.6789012 -0600 (GMT-6)
crtime: 2025-01-02 03:04:05.6789012 -0600 (GMT-6)

PS > statpp '\??\C:\test' attrs '-READONLY,+HIDDEN'
...
attrs : ["ARCHIVE", "HIDDEN"]
...

PS > statpp '\Device\HarddiskVolume6\test' ctime '2025-05-06 07:08:09.0123456 +0800'
...
ctime : 2025-05-05 18:08:09.0123456 -0500 (GMT-5)
...
```

### Build

- Command: `cl /O2 /EHsc /std:c++latest /W4 /sdl /I "${env:WindowsSDKDir}Include\${env:WindowsSDKVersion}km" statpp.cpp ntdll.lib`
- Dependencies: Windows Driver Kit (WDK) ([Download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))
- Compiler Support:
  |Compiler|Minimum Version|Required Options|
  |-|-|-|
  |cl (MSVC)|19.42|`/EHsc /std:c++latest /I "${env:WindowsSDKDir}Include\${env:WindowsSDKVersion}km" (/link) ntdll.lib`|
  |g++ (MinGW)|14 (`Formatting Ranges` not supported)|`-std=c++26 -isystem '<GCC root>\x86_64-w64-mingw32\include\ddk' -lstdc++exp -lntdll`|
  |clang++ (MSVC)|17 (with MSVC toolchain)|`-std=c++26 -isystem "${env:WindowsSDKDir}Include\${env:WindowsSDKVersion}km" -lntdll --target=x86_64-pc-windows-msvc`|

## statreg.cpp

### Description

- This tool gets/sets the timestamps of a registry key.
- Registry key timestamps include:
  - LastWriteTime/mtime
- Similar to [`privilege.cpp`](#privilegecpp), this tool can bypass all ACL checks.
- This tool also supports deleting a registry key, which is more powerful than [`privilege delkey`](#privilegecpp).

### Usage

```
Usage: "E:\program\statreg.exe" <registry> [<field> <value>]|[delete]
field: mtime
time : "%F %T %z" (yyyy-mm-dd HH:MM:SS.SSSSSSS ±zzzz)
```

- `<registry>`: The path to a registry key. It can be specified as either an NT path or a Win32 path.
  - NT path
    - `\Registry\Machine\...`, `\Registry\User\...`
  - Win32 path
    - `HKCR\...`, `HKCU\...`, `HKLM\...`, `HKCC\...`, `HKU\...`
    - `HKCR:\...`, `HKCU:\...`, `HKLM:\...`, `HKCC:\...`, `HKU:\...`
    - `HKEY_CLASSES_ROOT\...`, `HKEY_CURRENT_USER\...`, `HKEY_LOCAL_MACHINE\...`, `HKEY_CURRENT_CONFIG\...`, `HKEY_USERS\...`
    - `Registry::HKEY_CLASSES_ROOT\...`, `Registry::HKEY_CURRENT_USER\...`, `Registry::HKEY_LOCAL_MACHINE\...`, `Registry::HKEY_CURRENT_CONFIG\...`, `Registry::HKEY_USERS\...`
- If `<registry>` is a symbolic link, it will not be followed.
- `<field> <value>`: If specified, this tool will set the value of the specified field. Otherwise, this tool will get the values of all fields.
- `time`: The timestamp to set. The format `"%F %T %z"` is described in the [cppreference](https://en.cppreference.com/w/cpp/chrono/file_clock/formatter).
- `delete`: If specified, this tool will delete the registry key. The registry key must not have subkeys. Symbolic links will not be followed.

### Examples

```
PS > statreg HKCU:\Software\Classes\
\Registry\User\S-1-5-21-1519899142-224218750-2179000946-1001\Software\Classes\
LastWriteTime: 2025-01-02 03:04:05.6789012 -0600 (GMT-5)
TitleIndex   : 0
NameLength   : 14
Name         : Classes

PS > statreg 'Registry::HKEY_CLASSES_ROOT\test\' mtime '2025-05-06 07:08:09.0123456 +0800'
...
LastWriteTime: 2025-05-05 18:08:09.0123456 -0500 (GMT-5)
...

PS > statreg \Registry\Machine\test delete
```

### Build

- Command: `cl /O2 /EHsc /std:c++latest /W4 /sdl /I "${env:WindowsSDKDir}Include\${env:WindowsSDKVersion}km" statreg.cpp ntdll.lib`
- Dependencies: Windows Driver Kit (WDK) ([Download](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))
- Compiler Support:
  |Compiler|Minimum Version|Required Options|
  |-|-|-|
  |cl (MSVC)|19.37|`/EHsc /std:c++latest /I "${env:WindowsSDKDir}Include\${env:WindowsSDKVersion}km" (/link) ntdll.lib`|
  |g++ (MinGW)|14|`-std=c++26 -isystem '<GCC root>\x86_64-w64-mingw32\include\ddk' -lstdc++exp -lntdll`|
  |clang++ (MSVC)|17 (with MSVC toolchain)|`-std=c++26 -isystem "${env:WindowsSDKDir}Include\${env:WindowsSDKVersion}km" -lntdll --target=x86_64-pc-windows-msvc`|

## Microsoft.PowerShell_profile.ps1

### Description

- PowerShell configuration file. The absolute path is specified by the PowerShell variable `$PROFILE`.
- PowerShell version: 7.4+
- For more information, run `help <command>` for each customized command specified below.

### Functionalities

- `$PSDefaultParameterValues`
  - `Copy-Item: Confirm`: When copying a single item to a single destination, prompt for confirmation only if the destination item exists; otherwise, always prompt for confirmation.
  - `Remove-*: Confirm`: `$true`.
  - `Format-Table: AutoSize`: `$true`.
  - `Format-Table: Wrap`: `$true`.
- Aliases
  - `alias` -> `Get-Alias`
  - `date` -> `Get-Date`
- `ErrorView`: `NormalView`
- `function prompt`
  - Customize the prompt.
  - Display the current user, domain and working directory.
  - If the prompt is too long, the cursor for input will be placed on the next line.
  - Place a separating line filled with `-` between each command for better readability.
  - Keep a detailed history log for each command, including the command itself, its working directory, its execution time, its exit code, etc. To enable this feature, run `Set-PSReadLineOption -HistorySaveStyle SaveIncrementally`.
- `function bg`
  - Create a new process to run the specified command. The command will be run in a new console window.
  - The command should be wrapped in a script block. For example, `bg {ssh user@host}`.
- `function sudo`
  - Run the specified command as a different user.
  - The command should be wrapped in a script block. For example, `sudo {whoami}`.
  - Without `-AsTask`, a new process will be created to run the command as an administrator.
    - With `-Interactive`, the command will be run in a new console window, which allows user input.
    - Without `-Interactive`, the output of the command will be sent to the current console window, and user input is not allowed.
  - With `-AsTask`, the command will be run as a scheduled task. The output of the command will be sent to the current console window, and user input is not allowed. You must be an administrator to specify this option.
    - With `-RunAs <User>`, the command will be run as the specified user. `<User>` can be a user name or a SID, such as `NT AUTHORITY\SYSTEM`, `SYSTEM`, `SY`, `S-1-5-18`, `NT SERVICE\TrustedInstaller`, `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`, etc.
    - Without `-RunAs <User>`, the command will be run as `NT AUTHORITY\SYSTEM`.
  - With `-PreserveEnvironment`, the environment variables, PowerShell variables and PowerShell functions will be preserved.
  - ~~Dependencies: `tcp-receive.py`, `tcp-send.py`. Make sure `python.exe`, `tcp-receive.py` and `tcp-send.py` are in `$env:Path`. These scripts are used to send/receive data between the current process and the new process.~~ Inter-process communication is reimplemented using named pipes. No dependencies are required.
- `function New-Shortcut`: Create a shortcut for a file/url.
- `class ArgumentToEncodingTransformationAttribute`: Convert an argument to a specified encoding.
- `function slspp`: Beautify the output of `Select-String`.

## sqlite3.js

### Description

- This tool allows users to execute SQL queries on a SQLite database file.
- You can use this tool to read/write application data stored in SQLite databases. For example,
  - Microsoft Edge history (browsing history, download history, etc.): `C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History`
  - Visual Studio Code global state (recently opened projects/files, etc.): `C:\Users\<user>\AppData\Roaming\Code\User\globalStorage\state.vscdb`

### Usage

```
usage: sqlite3.js [-h] [-f FILE]

SQLite3 console

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  path to the SQLite3 database file
```

### Run

- Command: `node sqlite3.js -f <database file>`
- Dependencies: `argparse`, `sqlite`, `sqlite3`
- Install dependencies: `npm install argparse sqlite sqlite3`

## WinRAR-keygen.py

### Description

- This tool generates a valid WinRAR license key.
- Disclaimer: This tool is for educational purpose only. Please purchase a legitimate license key if you need to use WinRAR.
- [Mathematical Principle](https://github.com/bitcookies/winrar-keygen/blob/master/README.HOW_DOES_IT_WORK.md)

### Usage

```
Usage: python WinRAR-keygen.py <user name> <license type>
```

- `<user name>`: The name of the user who owns the license key. Actually, this field can be any string.
- `<license type>`: The type of the license key. Actually, this field can be any string.
- Move the generated license key file `rarreg.key` to WinRAR's installation directory (typically `C:\Program Files\WinRAR`).

### Run

- Command: `python WinRAR-keygen.py <user name> <license type>`
- Dependencies: `hashlib`, `zlib`
