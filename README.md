![MaliciousFileDetector logo](https://mauricelambert.github.io/info/go/security/MaliciousFileDetector_small.png "MaliciousFileDetector logo")

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
MaliciousFileDetector --no-color
```

## Links

 - [Executable - Github](https://github.com/mauricelambert/MaliciousFileDetector/releases/latest/)
 - [Executable - SourceForge](https://sourceforge.net/projects/MaliciousFileDetector/files/)

## Screenshot

![MaliciousFileDetector screen](https://mauricelambert.github.io/info/go/security/MaliciousFileDetectorDemo.png "MaliciousFileDetector screen")

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
