# VeraCrypt-Sniff
## Disclaimer
This is a proof-of-concept project created as a final project for the Sektor7 Institute - Malware Development Intermediate course. This was created for **EDUCATIONAL** purposes only! I do not condone the usage of any of this code copied or modified for any malicious purposes.

---

## Description
The goal of this project was to hook into the VeraCrypt process in order to sniff passwords for encrypted volumes. It achieves this through a 3 stage process. The stages are explained more in-depth below.

---

## Stages
### Stage 1: VCLoader
The loader is an executable. It includes the VCMigrate payload that's AES-256 encrypted. This loader simply decrypts the VCMigrate payload in memory and performs EarlyBird APC injection by creating a WerFault process. Additionally, all Windows APIs are dynamically loaded using GetModuleHandle()->GetProcAddress() and all strings are obfuscated using Adam Axley's compile-time string obfuscation. [Link](https://github.com/adamyaxley/Obfuscate)

---

### Stage 2: VCMigrate
This payload is a DLL that is prepended with shellcode. It uses Shellcode Reflective DLL Injection (sRDI) once injected by VCLoader into WerFault. It includes the VCSniff payload that's AES-256 encrypted. When executed it will perform a named pipe check to make sure only one process is running. It will also look for a list of processes related to analysis tools and will exit if any are present. If these checks are passed, it will constantly look for the VeraCrypt process to spawn. If not present, it will sleep for 5 seconds and look again infinitely. Once the VeraCrypt process is found, it will decrypt the VCSniff payload and inject it into VeraCrypt using simple CreateRemoteThread() injection and exit.

---

### Stage 3: VCSniff
This is the final payload. It's another DLL that uses sRDI to execute. Once executed within the VeraCrypt process, it will hook into the WideCharToMultiByte() using IAT hooking. It will collect the password that the user typed by using that hook and store it in a file in the APPDATA\Local\Temp\ directory.
