# File Guardian

**Real-time file monitoring and preservation system designed to capture malware samples before deletion**

[
[
[
[

## Overview

File Guardian is a specialized forensic tool built for malware analysts and security researchers. It monitors specified directories and automatically captures copies of files—**even those that are rapidly created and deleted**—using hardlink protection and aggressive file streaming techniques.

### Key Features

- 🛡️ **Hardlink Protection** - Creates instant hardlinks to prevent file deletion
- ⚡ **Rapid Capture** - 200ms debounce window catches files before malware can delete them
- 🔒 **Locked File Handles** - Maintains file access during copying to prevent tampering
- 📋 **SHA-256 Hashing** - Automatic integrity verification for all captured files
- 🔄 **Recovery Mode** - Attempts to recover files even after deletion events
- 📊 **Detailed Logging** - Timestamped metadata logs with file paths, sizes, and hashes
- 🎯 **Selective Monitoring** - Configurable paths, file size limits, and retry logic


## Use Cases

- **Malware Analysis** - Capture self-deleting malware samples during execution
- **Incident Response** - Preserve evidence before adversaries can destroy it
- **Forensic Investigation** - Monitor and backup critical directories in real-time
- **Threat Hunting** - Capture suspicious file activity in monitored environments


## How It Works

### Capture Strategy

1. **Hardlink Creation** (Primary Method)
    - Creates NTFS hardlinks instantly when files are detected
    - Prevents deletion until all hardlinks are removed
    - Zero-copy operation for maximum speed
2. **Stream Copy with Locked Handle** (Fallback)
    - Opens file with aggressive sharing flags
    - Maintains read handle during entire copy operation
    - Prevents modification or deletion during capture
3. **Staged Recovery**
    - Maintains staging area for in-progress captures
    - Recovers partial captures when deletion is detected
    - Finalizes staged files with integrity verification

### Architecture

```
FileSystemWatcher → Debounce Queue → Capture Engine → Backup Storage
                                           ├─ Hardlink (instant)
                                           ├─ Stream Copy (locked)
                                           └─ SHA-256 Hash
```


## Installation

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- .NET 6.0 Runtime or later
- Administrator privileges (required for hardlink creation)


### Build from Source

```bash
git clone https://github.com/yourusername/file-guardian.git
cd file-guardian
dotnet build -c Release
```


### Binary Release

Download the latest release from the [Releases](https://github.com/yourusername/file-guardian/releases) page.

## Configuration

Edit the configuration constants at the top of `Program.cs`:

```csharp
// Monitor this directory (recursively)
private static readonly string monitorPath = @"C:\Users\zbs-lab-d\AppData\";

// Save captured files here
private static readonly string backupPath = @"C:\Backup\Captured";

// Debounce delay (ms) - how long to wait for file to stabilize
private static readonly int debounceMs = 200;

// Maximum retry attempts for locked files
private static readonly int maxRetries = 5;

// Skip files larger than this (1GB default)
private static readonly long maxFileSizeBytes = 1000 * 1024 * 1024;
```


## Usage

### Running File Guardian

**⚠️ Must be run as Administrator for hardlink creation**

```bash
# Run directly
FileGuardian.exe

# Or via dotnet
dotnet run --project FileGuardian.csproj
```


### Output Structure

```
C:\Backup\Captured\
├── _logs\
│   └── capture_20241123.log          # Daily metadata logs
├── _staging\
│   └── temp_*.tmp                     # Temporary staging files
└── [mirrored directory structure]
    └── malware_20241123_102945_123.exe  # Timestamped captures
```


### Metadata Logs

Each captured file is logged with:

```
2024-11-23 10:29:45.123|C:\Source\file.exe|C:\Backup\file_20241123_102945.exe|524288|a3f5b1c8...
```

Format: `Timestamp|SourcePath|DestPath|SizeBytes|SHA256Hash`

## Security Considerations

### Permissions Required

- **Administrator** - Required for `CreateHardLink()` API calls
- **Write Access** - Backup destination must be writable
- **Read Access** - Monitor path must be readable


### Malware Handling

⚠️ **WARNING**: This tool is designed for controlled malware analysis environments.

- Always run in **isolated VMs** or **sandboxed environments**
- Captured files retain their original malicious nature
- Use proper **endpoint protection** on backup storage
- Consider **network isolation** for analysis systems


### Performance Impact

- Uses 64KB `FileSystemWatcher` buffer (larger than default)
- Async/await pattern for non-blocking operations
- Hardlinks have near-zero performance cost
- Stream copies use 80KB buffers for efficiency


## Advanced Features

### Event Detection

Monitors these filesystem events:

- File creation
- File modification
- File renaming
- File deletion (triggers recovery attempt)


### Collision Handling

Files with identical names get unique timestamps:

```
malware.exe → malware_20241123_102945_123.exe
malware.exe → malware_20241123_102945_456.exe
```


### Deletion Recovery

If a file is deleted during capture:

1. Checks staging area for hardlink
2. Marks file as `_RECOVERED` in filename
3. Finalizes copy with integrity hash

## Troubleshooting

### "Access Denied" Errors

- Ensure running as **Administrator**
- Check NTFS permissions on monitor and backup paths
- Verify antivirus isn't blocking file access


### Files Not Being Captured

- Increase `debounceMs` for slower filesystems
- Check `maxFileSizeBytes` limit
- Verify `monitorPath` is correct
- Review console output for error messages


### High CPU/Memory Usage

- Reduce `InternalBufferSize` if monitoring high-traffic directories
- Increase `debounceMs` to reduce event processing
- Add file extension filters to `FileSystemWatcher.Filter`


## Keyboard Commands

- **Q** - Quit File Guardian gracefully


## Development

### Technology Stack

- **Language**: C\# 10.0
- **Framework**: .NET 6.0+
- **APIs**: Win32 Kernel32.dll (P/Invoke), FileSystemWatcher
- **Async**: Task Parallel Library (TPL)


### Architecture Patterns

- Concurrent collections for thread-safe event queuing
- Debounce pattern to handle rapid file changes
- Retry logic with exponential backoff
- Strategy pattern for capture methods (hardlink → stream copy)


## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Built for malware analysis workflows at **ZBS Labs LLC**

## Disclaimer

This tool is intended for **authorized security research and malware analysis only**. Users are responsible for:

- Complying with applicable laws and regulations
- Obtaining proper authorization before monitoring systems
- Safely handling captured malware samples
- Maintaining appropriate security controls

**Use at your own risk. The authors assume no liability for misuse or damages.**

***

**Built with 🛡️ for the cybersecurity community**
