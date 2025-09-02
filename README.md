# RitzyScanner

A Windows-based tool for **process memory scanning**, **file signature verification**, **Jumplist parsing**, **service scanning**, and **registry checks** for forensic and security purposes.

## Features

1. **Process Memory Scanner**
   - Scans all running processes for executable, DLL, SYS, and script files in memory.
   - Checks each file for:
     - File existence
     - Modification timestamp
     - Signature validity (Authenticode / Catalog / Invalid)
     - Trust status (Trusted / Untrusted / Unsigned)
   - Exports results to a CSV file named `ProcessMemoryScan_YYYYMMDD_HHMMSS.csv`.

2. **Jumplist Parser**
   - Parses Windows Jumplist files (`.automaticDestinations-ms` and `.customDestinations-ms`) from the current user.
   - Extracts:
     - File paths, arguments, icons, timestamps
     - Signature verification and trust status
   - Exports results to:
     - `Automatic-Jumplists.csv`
     - `Custom-Jumplists.csv`

3. **Service Scanner**
   - Enumerates Windows services (`PcaSvc`, `DiagTrack`, `WSearch`, `WinDefend`, `wuauserv`, `EventLog`, `Schedule`) and checks memory for files.
   - Retrieves service PIDs and associates files found in memory with their source service.

4. **Registry Checks**
   - Reads and parses important Windows registry entries for execution proof and file paths / existance of files

5. **FiveM / GTAV Checks**
   - Basic FiveM checks that look for Meta files in AI folder, D3D10.dll in plugins, Bigger Hitboxes x64a.rpf file in GTAV directory.

6. **File Verification & Security**
   - Checks digital signatures of all files discovered.
   - Flags untrusted or unsigned files, even if a certificate exists but is not valid.
   - Trusted files are valid Authenticode or catalog-signed files.

---

## Usage

1. Run the compiled executable as **Administrator**.
2. Open CSV files in Timeline Explorer, or any CSV reader for analysis.

---

## Notes

- **Administrator Privileges Required**: Full process and service scanning requires debug privileges.
- **File Trust & Signature**:
  - `Trusted`: Valid Authenticode / Catalog signature
  - `Untrusted`: No signature or invalid certificate
  - `Unsigned`: File without a certificate
- **Registry & FiveM Checks**:
  - Detects common cheat/bypass artifacts in GTAV/FiveM installations.
  - Scans memory and service directories for suspicious files.

---

## VirusTotal

- The main executable has been checked on VirusTotal and is **100% clean**:  
[VirusTotal Scan](https://www.virustotal.com/gui/file/5cf721f8d1fe885e1c3b6a7c93988ff4208e8c518b3f6b407b8c1a97347bd684?nocache=1)

---

## License

- Open-source (MIT License recommended)
- Free for personal and forensic use
