# ForensicsScanner

A comprehensive Windows forensics tool designed for analyzing system artifacts and detecting potential cheats/malware, particularly in gaming environments like GTA V and FiveM.

## Description

ForensicsScanner is a C++ application that performs multiple types of forensic analysis on Windows systems. It scans registry entries, process memory, jump lists, Windows services, prefetch files, and specific directories for suspicious activity. The tool is particularly useful for anti-cheat detection in online gaming communities.

## Features

### 1. Registry Parser
- Parses Windows registry for application execution history
- Analyzes MuiCache entries for recently accessed applications
- Checks file signatures and trust status
- Extracts modification times, user information, and file metadata
- **Output**: `Registry.csv`

### 2. Process Scanner
- Scans memory of all running processes for file references
- Converts device paths to drive letters
- Performs signature verification on referenced files
- Identifies file modification times and existence status
- **Output**: `ProcessMemoryScan_<timestamp>.csv`

### 3. Jump List Parser
- Analyzes Windows Jump Lists (.lnk files) from user profiles
- Extracts file paths, titles, arguments, and working directories
- Includes icon information and file metadata
- Performs signature checks and trust verification
- Calculates SHA256 hashes and file sizes
- **Output**: `Jumplists.csv`

### 4. Service Scanner
- Checks the status of critical Windows services
- Reports running/stopped/error states for key system services
- **Output**: `Services.csv`

### 5. PCA App Launch Parser
- Parses Program Compatibility Assistant (PCA) data
- Extracts application launch information and metadata
- Includes file signatures, trust status, and timestamps
- Calculates SHA256 hashes and file sizes
- **Output**: `PcaAppLaunch.csv`

### 6. Prefetch Analyzer
- Analyzes Windows Prefetch files for system activity
- Detects suspicious prefetch entries and deleted files
- Checks prefetch registry settings
- Performs multi-threaded analysis for performance
- **Output**: `prefetch_analysis.csv`
- **Note**: Requires administrator privileges

### 7. Direct Finds Scanner
- Uses YARA-like rules to scan specific directories
- Targets FiveM and GTA V installation folders
- Detects cheat files, mods, and suspicious modifications
- Includes file metadata, signatures, and hash verification
- **Output**: `DirectFinds.csv`

### 8. Advanced Memory Scanner
- Scans memory of specific processes and services
- Targets: explorer.exe, PcaSvc (Program Compatibility Assistant), DPS (Diagnostic Policy Service), Dnscache
- Detects cheat-related strings and patterns
- Supports Unicode, Extended Unicode, and ASCII pattern matching
- Uses multi-threaded scanning for performance
- Minimum pattern length: 5 characters
- **Note**: Integrated into the main scanning process

## Requirements

- Windows operating system
- Visual Studio 2019 or later (for building)
- Administrator privileges (recommended for full functionality)
- C++17 compatible compiler

## Building

1. Open the `ForensicsScanner.vcxproj` file in Visual Studio
2. Select the appropriate build configuration (Release recommended)
3. Build the solution
4. The executable will be generated in `x64/Release/ForensicsScanner.exe`

## Usage

1. Run the executable as administrator for best results
2. The tool will automatically perform all scans in sequence
3. Progress is displayed in the console
4. Results are saved to CSV files in the same directory as the executable

### Command Line
```
ForensicsScanner.exe
```

The tool runs automatically and requires no command-line arguments.

## Output Files

All results are exported to CSV files for easy analysis:

- `Registry.csv` - Registry analysis results
- `ProcessMemoryScan_<timestamp>.csv` - Process memory scan results
- `Jumplists.csv` - Jump list analysis results
- `Services.csv` - Service status information
- `PcaAppLaunch.csv` - PCA application launch data
- `prefetch_analysis.csv` - Prefetch file analysis
- `DirectFinds.csv` - Direct file scan results

## Important Notes

- **Administrator Privileges**: Some features (especially Prefetch Analyzer) require running as administrator
- **Performance**: Memory scanning can be resource-intensive on systems with many processes
- **False Positives**: Some detections may be legitimate system activity
- **Legal Use**: This tool is intended for legitimate forensic analysis and anti-cheat purposes only

## Detection Patterns

The memory scanner includes extensive pattern matching for known cheats and suspicious activity, including:

- File path detections (drive letters, specific directories)
- Cheat engine signatures
- Mod files and scripts
- Bypass tools and spoofers
- Network-related cheat indicators

## Contributing

This is a specialized forensics tool. Contributions should focus on:
- Improving detection accuracy
- Adding new forensic analysis methods
- Performance optimizations
- Cross-platform compatibility (if applicable)

## License

[Add your license information here]

## Disclaimer

This tool is provided for educational and legitimate forensic purposes. Users are responsible for complying with applicable laws and regulations when using this software.