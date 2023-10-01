// This scripts detects suspicious and probably malicious files
// used to attack your system

/*
    Copyright (C) 2023  Maurice Lambert
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Compilation on Linux:
// env GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o GetMaliciousFiles.exe GetMaliciousFiles.go

package main

import (
    "os"
    "fmt"
    "math"
    "regexp"
    "unsafe"
    "strings"
    "syscall"
    "io/ioutil"
    "path/filepath"
    "container/list"
    "encoding/binary"
)

var root_startswith_whitelist []string = []string{
    "C:\\Drivers",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\Windows",
    "C:\\$Recycle.Bin",
    "C:\\Drivers",
    "C:\\Intel",
    "C:\\PerfLogs",
    "C:\\Recovery",
    "C:\\temp",
    "C:\\Users",
    "C:\\Config.Msi",
}

var suspicious_files_counter uint = 0
var malicious_files_counter uint = 0
var analyzed_files_counter uint = 0
var discover_files map[string]bool
var function uintptr = 0
var pourcent byte = 1

/*
    This function checks if path is in directories whitelist.
*/
func check_whitelist_paths (path string) bool {
    for _, whitelisted_path := range root_startswith_whitelist {
        if (strings.HasPrefix(path, whitelisted_path)) {
            return true
        }
    }
    return false
}

/*
    This function returns matching filenames.
*/
func get_files_by_patterns(pattern string) []string {
    matches, error := filepath.Glob(pattern)

    if error != nil {
        fmt.Fprintf(os.Stderr, "Error getting files: %v\n", error)
        return nil
    }

    files := make([]string, len(matches))
    index := 0

    for _, filename := range matches {
        fileInfo, error := os.Stat(filename)
        if error != nil {
            fmt.Fprintf(os.Stderr, "Error getting stat file: %v\n", error)
            continue
        }

        if !fileInfo.IsDir() && fileInfo.Size() > 256 {
            _, ok := discover_files[filename]
            if !ok {
                files[index] = filename
                index += 1
            }
        }
    }

    return files
}

/*
    This function returns all suspicious filenames in path and subdirectories.
*/
func get_suspicious_filename(
    path string, extensions []string, suspicious_files []string,
) []string {
    files := get_subfiles(path)

    for file := files.Front(); file != nil; file = file.Next() {

        filename := file.Value.(string)
        _, ok := discover_files[filename]
        if ok {
            continue
        }

        analyzed_files_counter += 1
        for _, extension := range extensions {
            if strings.HasSuffix(filename, extension) {
                suspicious_files = append(suspicious_files, filename)
                discover_files[filename] = true
            }
        }
    }

    return suspicious_files
}

/*
    This function matchs dangerous files (executables, scripts, librairies)
    in temp directories, data directories and public directories.
*/
func get_suspicious_file_by_extension () []string {
    suspicious_files := []string{}
    paths := []string{
        "C:\\temp\\",
        "C:\\ProgramData\\",
        "C:\\Users\\Public\\",
    }
    extensions := []string{
        ".dll", ".exe", ".ps1", ".vbs", ".js", ".cmd", ".bat",
    }

    paths_, error := filepath.Glob("C:\\Users\\*\\AppData\\Local\\Temp\\")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error getting files: %v\n", error)
        return nil
    }
    paths = append(paths, paths_...)

    paths_length := len(paths)
    for index, path := range paths {
        pourcent = byte(int(index * 25 / paths_length))
        messagef(
            fmt.Sprintf("Scanning %s...", path),
            "INFO",
        )

        suspicious_files = get_suspicious_filename(
            path, extensions, suspicious_files,
        )
    }

    return suspicious_files
}
/*
    This function returns executables files in specific directories.
*/
func get_executable_files(paths []string) []string {
    executable_files := []string{}
    paths_length := len(paths)

    for index, path := range paths {
        pourcent = byte(int(index * 13 / paths_length) + 50)
        messagef(
            fmt.Sprintf("Scanning %s...", path),
            "INFO",
        )

        files := get_subfiles(path)
        for file := files.Front(); file != nil; file = file.Next() {
            filename := file.Value.(string)

            _, ok := discover_files[filename]
            if ok {
                continue
            }

            analyzed_files_counter += 1
            if is_executable(filename) {
                executable_files = append(executable_files, filename)
                discover_files[filename] = true
            }
        }
    }

    return executable_files
}

/*
    This function returns executables files in specific root directories.
*/
func get_root_executable_files(executable_files []string) []string {
    root_directories, error := os.ReadDir("C:\\")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error getting files: %v\n", error)
        return executable_files
    }

    paths_length := len(root_directories)
    for index, path := range root_directories {

        pathname := "C:\\" + path.Name()
        if check_whitelist_paths(pathname) {
            continue
        }
        pourcent = byte(int(index * 12 / paths_length) + 63)
        messagef(
            fmt.Sprintf("Scanning %s...", pathname),
            "INFO",
        )

        files := get_subfiles(pathname)
        for file := files.Front(); file != nil; file = file.Next() {
            filename := file.Value.(string)

            _, ok := discover_files[filename]
            if ok {
                continue
            }

            analyzed_files_counter += 1
            if is_executable(filename) {
                executable_files = append(executable_files, filename)
                discover_files[filename] = true
            }
        }
    }

    return executable_files
}

/*
    This function returns executable files in TEMP directories, data
    directories, root directories and public directories.
*/
func get_suspicious_executable_files () []string {    
    paths := []string{
        "C:\\temp",
        "C:\\Users\\Public",
        "C:\\ProgramData",
    }
    paths_, error := filepath.Glob("C:\\Users\\*\\AppData\\Roaming")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error getting files: %v\n", error)
        return nil
    }
    paths = append(paths, paths_...)

    paths_, error = filepath.Glob("C:\\Users\\*\\AppData\\Local")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error getting files: %v\n", error)
        return nil
    }
    paths = append(paths, paths_...)

    executable_files := get_executable_files(paths)
    executable_files = get_root_executable_files(executable_files)
    return executable_files
}

/*
    This function returns files recursively.
*/
func get_subfiles(directory string) *list.List {
    files := list.New()

    filepath.Walk(
        directory,
        func(path string, file os.FileInfo, error error) error {

            if error != nil || file.Size() < 256 {
                if error != nil {
                    fmt.Fprintf(
                        os.Stderr,
                        "Error getting path recursively (%s): %v\n",
                        path,
                        error,
                    )
                }
                return nil
            }

            if !file.IsDir() {
                files.PushFront(path)
            }

            return nil
        },
    )

    return files
}

/*
    This function tests if file is a Windows executable file.
*/
func is_executable(filename string) bool {
    file, error := os.Open(filename)
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error opening file %s: %v\n", filename, error)
        return false
    }
    defer file.Close()

    bytes := make([]byte, 64)
    _, error = file.Read(bytes)
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filename, error)
        return false
    }

    if bytes[0] != 0x4d || bytes[1] != 0x5a {
        return false
    }

    _, error = file.Seek(
        int64(binary.LittleEndian.Uint32(bytes[0x3c:0x40])), 0,
    )
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error seeking file %s: %v\n", filename, error)
        return false
    }

    bytes = make([]byte, 4)
    _, error = file.Read(bytes)
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filename, error)
        return false
    }

    if bytes[0] != 0x50 || bytes[1] != 0x45 ||
       bytes[2] != 0x00 || bytes[3] != 0x00 {
        return false
    }
    return true
}

/*
    This function checks for long encoded strings in executable.
*/
func have_long_encoded_data(content []byte) bool {
    /*regex_base16, error := regexp.Compile("[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}[0-9a-fA-F]{255}")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error compiling base16 regex: %v\n", error)
        return false
    }

    regex_base32, error := regexp.Compile("[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}[A-Z0-7]{255}")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error compiling base32 regex: %v\n", error)
        return false
    }*/ // base64 regex match base32 and base16, there is few executables that match theses regex so delete this regex is probably more optimized.

    regex_base64, error := regexp.Compile("[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}[A-Za-z0-9+/_-]{255}")
    if error != nil {
        fmt.Fprintf(os.Stderr, "Error compiling base64 regex: %v\n", error)
        return false
    }

    /*if regex_base16.FindIndex(content) != nil {
        return true
    }

    if regex_base32.FindIndex(content) != nil {
        return true
    }*/

    if regex_base64.FindIndex(content) != nil {
        return true
    }
    return false
}

/*
    This function checks file for very high entropy.
*/
func have_suspicious_entropy(content []byte) bool {
    frequencies := make(map[byte]int)
    for _, character := range content {
        frequencies[character]++
    }

    var score float64
    length := len(content)
    for _, frequency := range frequencies {
        p := float64(frequency) / float64(length)
        score += -p * math.Log2(p)
    }

    if score > 7.2 {
        return true
    } else {
        return false
    }
}

/*
    This function checks content for malicious payload.
*/
func have_suspicious_content (filename string, executable bool) bool {
    if executable || is_executable(filename) {
        content, error := ioutil.ReadFile(filename)
        if error != nil {
            fmt.Fprintf(
                os.Stderr, "Error reading file %s: %v\n", filename, error,
            )
            return false
        }

        if have_suspicious_entropy(content) {
            return true
        }

        if have_long_encoded_data(content) {
            return true
        }
    } else {
        fileInfo, error := os.Stat(filename)
        if error != nil {
            fmt.Fprintf(os.Stderr, "Error getting stat file: %v\n", error)
            return false
        }

        if fileInfo.Size() > 100000 {
            return true
        }
    }

    return false
}

/*
    This function loads the TerminalMessages DLL.
*/
func getTerminalMessages() (uintptr, error) {
    executable, error := os.Executable()

    if error == nil {
        terminalMessages, error := syscall.LoadLibrary(
            filepath.Join(filepath.Dir(executable), "TerminalMessages.dll"),
        )

        if error == nil {
            function, error = syscall.GetProcAddress(
                terminalMessages, "messagef",
            )
            if error == nil {
                return function, nil
            }
        }
    }

    directory, error1 := os.Getwd()

    if error1 == nil {
        terminalMessages, error1 := syscall.LoadLibrary(
            filepath.Join(directory, "TerminalMessages.dll"),
        )

        if error1 == nil {
            function, error = syscall.GetProcAddress(
                terminalMessages, "messagef",
            )
            if error1 == nil {
                return function, nil
            }
        }
    }

    return 0, error
}

/*
    This function is a wrapper for TerminalMessages.messagef function.
*/
func messagef(message string, state string) {
    if function == 0 {
        if state != "INFO" {
            fmt.Println(message)
        }
        return
    }

    var add_progress_bar byte = 1
    if pourcent == 0 {
        add_progress_bar = 0
    }

    messagebytes := append([]byte(message), 0)
    statebytes := append([]byte(state), 0)
    _, _, error := syscall.Syscall9(
        function,
        8,
        uintptr(unsafe.Pointer(&messagebytes[0])),
        uintptr(unsafe.Pointer(&statebytes[0])),
        uintptr(pourcent),
        0,
        0,
        0,
        uintptr(add_progress_bar),
        0,
        0,
    )

    if error != 0 && state != "INFO" {
        fmt.Println(message)
    }
}

func parse_args() {
    if len(os.Args) != 2 && len(os.Args) != 1 {
        fmt.Fprintf(os.Stderr, "USAGES: %s [-c/--no-color]\n", os.Args[0])
        os.Exit(1)
    }

    var error error = nil

    if len(os.Args) == 2 {
        if os.Args[1] != "-c" && os.Args[1] != "--no-color" {
            fmt.Fprintf(os.Stderr, "USAGES: %s [-c/--no-color]\n", os.Args[0])
            os.Exit(1)
        }
    } else {
        function, error = getTerminalMessages()
    }

    if error != nil {
        fmt.Fprintf(os.Stderr, "Warning loading DLL: %v\n", error)
    }
}

/*
    This is the main fonction to run this script.
*/
func main() {
    parse_args()
    discover_files = make(map[string]bool)

    messagef("Start suspicious filenames...", "INFO")
    files := get_suspicious_file_by_extension()
    file_length := len(files)
    for index, file := range files {
        pourcent = byte(index * 25 / file_length) + 25
        if have_suspicious_content(file, false) {
            messagef(fmt.Sprintf("Malicious: %s", file), "ERROR")
            malicious_files_counter += 1
        } else {
            messagef(fmt.Sprintf("Suspicious: %s", file), "NOK")
            suspicious_files_counter += 1
        }
    }

    pourcent = byte(50)
    messagef("Search suspicious executables...", "INFO")
    files = get_suspicious_executable_files()
    file_length = len(files)
    for index, file := range files {
        pourcent = byte(index * 25 / file_length) + 75
        if (strings.HasSuffix(file, ".exe") ||
           strings.HasSuffix(file, ".mui") ||
           strings.HasSuffix(file, ".so") ||
           strings.HasSuffix(file, ".sys") ||
           strings.HasSuffix(file, ".vdm") ||
           strings.HasSuffix(file, ".lkg") ||
           strings.HasSuffix(file, ".efi") ||
           strings.HasSuffix(file, ".pyd") ||
           strings.HasSuffix(file, ".node") ||
           strings.HasSuffix(file, ".dll")) &&
           !have_suspicious_content(file, true) {
            messagef(fmt.Sprintf("Suspicious: %s", file), "NOK")
            suspicious_files_counter += 1
        } else {
            messagef(fmt.Sprintf("Malicious: %s", file), "ERROR")
            malicious_files_counter += 1
        }
    }

    pourcent = byte(100)
    messagef(
        fmt.Sprintf(
            "Analyzed files: %d, Detected files: %d, Suspicous files: %d, Malicious files: %d",
            analyzed_files_counter,
            len(discover_files),
            suspicious_files_counter,
            malicious_files_counter,
        ),
        "OK",
    )
}