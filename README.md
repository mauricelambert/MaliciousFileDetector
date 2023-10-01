![MaliciousFileDetector logo](https://mauricelambert.github.io/info/go/security/MaliciousFileDetector_small.gif "MaliciousFileDetector logo")

# MaliciousFileDetector

## Description

This scripts detects suspicious and probably malicious files used to attack your system.

> Initially this script have been used to detect scripts and DLLs used in Qakbot compromissions. Finally this script detects scripts, executables and DLLs in easy to write directories like: temp directories, data directories or root directories (the last one require admin permissions but QakBot can be write here).

## Requirements

### Download

 - *No requirements*

### Optional

 - [TerminalMessages DLL or Shared Object](https://github.com/mauricelambert/TerminalMessages/releases/latest/)

### Compilation

 - Go
 - Go Standard library

## Installation

### Download

Download the executable from [Github](https://github.com/mauricelambert/MaliciousFileDetector/releases/latest/) or [Sourceforge](https://sourceforge.net/projects/MaliciousFileDetector/files/).

### Compilation

```bash
git clone https://github.com/mauricelambert/MaliciousFileDetector.git
cd MaliciousFileDetector
go build MaliciousFileDetector.go
```

## Usages

```bash
MaliciousFileDetector
MaliciousFileDetector -c
MaliciousFileDetector --no-color > output.txt
```

### When you should use this script

1. When you get an anti-malware event on Windows Servers: this script help you to find malicious files and diagnostics the event as True Positive.
2. All days as *scheduled tasks*: this scripts help you to detect intrusion and bad administration practices, be careful this script returns lot of False Positive you probably should investigate only files detected as `Malicious`.
3. When you get an anti-malware event True Positive on Windows workstation: this script help you to find malicious files used to deploy and execute the malware on the work station. Be careful this script returns lot of False Positive, you should analyze the output to find files used for intrusion.

### How you should analyze the output

1. Some files are detected as `Malicious`, you should investigate or analyze theses files
2. Lot of files are detected as `Suspicious`, theses files are easy to use by hackers to compromise your system but it's probably False Positive, you should use suspicious files to check the filename (it may be present on this system ? it's an official files ? it's the real file ?) but you don't need to analyze all of suspicious files.

### What is suspicious files

1. Suspicious files are filenames in temp and data directory with extensions: `exe`, `dll`, `ps1`, `cmd`, `bat`, `vbs`, `js`. Scripts, libraries and executables may not be in temp or data folders (on workstation there are multiples applications *easy to install* than can be installed in theses folders but it's dangerous for privileges escalation and persistence).
2. MS-DOS PE files (files matching the executable format) in temp, data or root directories because executables files and libraries may not be in theses directories. The root directories is an exception, i add it for the first usage of this script, because Qakbot can be write in root directories (require admin permissions but Qakbot are installed in theses directories in multiples versions).

### What is malicious files

Malicious files are suspicious files with suspicious content:

1. An executable file with very high entropy (*shannon entropy* greater than `7.2`, to detect packed executables or encrypted payloads)
2. An executable file with very long (~> 5000 characters) base64, base32 or base16 data
3. An executable file with extensions different than (to bypass some antivirus checks file extension can be modified by hackers for DLL):
    - `exe`
    - `mui`
    - `so`
    - `sys`
    - `vdm`
    - `lkg`
    - `efi`
    - `pyd`
    - `node`
    - `dll`
4. A script greater than 1 MB (hackers use script ton encode and write or load DLLs)

## Links

 - [Executable - Github](https://github.com/mauricelambert/MaliciousFileDetector/releases/latest/)
 - [Executable - SourceForge](https://sourceforge.net/projects/MaliciousFileDetector/files/)

## Screenshot

![MaliciousFileDetector screen](https://mauricelambert.github.io/info/go/security/MaliciousFileDetectorDemo.png "MaliciousFileDetector screen")

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
