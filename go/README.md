# NTFS Parser

A comprehensive NTFS file system parser written in Go, designed for forensic analysis, data recovery, and security auditing.

## Overview

The NTFS Parser is a powerful tool for analyzing NTFS file systems, recovering deleted files, extracting metadata, and performing forensic investigations. It supports both physical drives and disk image files, making it versatile for various use cases.

## Features

### Core Functionality
- Parse and navigate NTFS file systems
- Support for both physical drives and disk image files
- Support for split image files (e.g., .001, .002, etc.)
- Automatic detection of NTFS partitions

### File Operations
- List all files and directories in the volume
- Recursive directory traversal
- Pattern-based file searching
- Support for listing deleted files
- Extract file content from MFT records
- Handle resident and non-resident attributes
- Support for fragmented files through data runs

### Metadata Analysis
- Extract file timestamps (creation, modification, access, MFT modification)
- File size information (logical size vs. allocated size)
- File attributes (hidden, system, compressed, encrypted)
- Calculate file entropy for potential encryption detection
- Generate file signatures/hashes (SHA256)

### Security Analysis
- Parse NTFS security descriptors
- Extract and interpret access control lists (ACLs)
- Analyze file permissions and ownership
- Interpret security identifiers (SIDs)

### Timeline Generation
- Create filesystem activity timelines
- Filter events by time range
- Support for different event types (creation, modification, access, deletion)
- Chronological sorting of filesystem events
- Export timeline to various formats (CSV, JSON, TXT)

### File Carving
- Recover files based on signatures/headers
- Support for various file types (JPEG, PNG, PDF, etc.)
- Carve files from unallocated space
- Output carved files to a specified directory

### USN Journal Analysis
- Parse the Update Sequence Number (USN) journal
- Extract change journal records
- Track file system changes over time
- Filter journal entries by timestamp or USN

### Performance Features
- Multi-threaded processing for better performance
- Chunked reading for large files
- Progress reporting for long-running operations
- Cancellation support for operations
- Optimized memory usage for large volumes
- Configurable buffer sizes for I/O operations

## Installation

### Prerequisites
- Go 1.21 or higher
- Windows, Linux, or macOS

### Building from Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ntfs_parser.git
cd ntfs_parser/go
```

2. Build the executable:
```bash
go build -o ntfsanalyze.exe ./cmd/ntfsanalyze
```

## Usage

### Command-Line Interface

The NTFS parser provides a command-line interface with various options:

```
NTFS Analyzer - A forensic tool for NTFS file systems
=====================================================

USAGE:
  ntfsanalyze [options]

BASIC OPTIONS:
  -device string      Path to NTFS volume or image file (required)
  -output string      Output directory for recovered files
  -help               Show this help information
  -buffer int         Buffer size for operations in bytes (default: 4MB)

FILE LISTING OPTIONS:
  -list               List files in the volume
  -pattern string     Search pattern (e.g., '*.txt')
  -deleted            Include deleted files
  -recursive          Recursive search in subdirectories

METADATA OPTIONS:
  -metadata string    Extract metadata for specific file

TIMELINE OPTIONS:
  -timeline           Generate filesystem timeline
  -start string       Timeline start time (YYYY-MM-DD)
  -end string         Timeline end time (YYYY-MM-DD)
  -events string      Event types to include (comma-separated, default: all)
                      Available types: creation,modification,access,mft,deletion

FILE CARVING OPTIONS:
  -carve              Perform file carving
  -carvetypes string  File types to carve (comma-separated)
                      Available types: JPEG,PNG,GIF,PDF,ZIP,DOC,XLS,PPT

JOURNAL OPTIONS:
  -journal            Parse USN journal
  -journalstart int   Starting USN for journal parsing
  -journalmax int     Maximum number of journal entries to return (default: 1000)

SECURITY OPTIONS:
  -security           Analyze file security
  -secfile string     File to analyze security for
```

### Examples

#### List all files in an NTFS volume:
```bash
ntfsanalyze -list -device /dev/sda1
```

#### List all files including deleted files:
```bash
ntfsanalyze -list -deleted -device /dev/sda1
```

#### Extract metadata for a specific file:
```bash
ntfsanalyze -metadata "path/to/file.txt" -device /dev/sda1
```

#### Generate a timeline of filesystem events:
```bash
ntfsanalyze -timeline -device /dev/sda1
```

#### Generate a timeline for a specific date range:
```bash
ntfsanalyze -timeline -start 2023-01-01 -end 2023-12-31 -device /dev/sda1
```

#### Carve files from the volume:
```bash
ntfsanalyze -carve -carvetypes "JPEG,PNG,PDF" -output ./carved_files -device /dev/sda1
```

#### Analyze file security:
```bash
ntfsanalyze -security -secfile "path/to/file.txt" -device /dev/sda1
```

#### Parse USN journal:
```bash
ntfsanalyze -journal -device /dev/sda1
```

## Using as a Library

The NTFS parser can also be used as a library in your Go projects:

```go
package main

import (
	"fmt"
	"github.com/ntfs_parser/pkg/ntfs"
)

func main() {
	// Open an NTFS volume
	volume, err := ntfs.NewNTFSVolume("/dev/sda1")
	if err != nil {
		fmt.Printf("Error opening volume: %v\n", err)
		return
	}
	defer volume.Close()

	// Create a scanner
	scanner := ntfs.NewScanner(volume)
	
	// Set progress callback for long operations
	scanner.SetProgressCallback(func(processed, total int64, status string) {
		fmt.Printf("\r%s - %.1f%% complete", status, float64(processed)/float64(total)*100)
	})

	// List files
	files, err := scanner.ListFiles(false)
	if err != nil {
		fmt.Printf("Error listing files: %v\n", err)
		return
	}

	// Print file information
	for _, file := range files {
		fmt.Printf("File: %s, Size: %d bytes, Created: %s\n",
			file.Name, file.Size, file.CreationTime)
	}
}
```

## Advanced Usage

### File Carving

The file carving feature allows you to recover files based on their signatures:

```bash
ntfsanalyze -carve -carvetypes "JPEG,PNG,PDF" -output ./carved_files -device /dev/sda1
```

Supported file types include:
- JPEG/JPG
- PNG
- GIF
- PDF
- ZIP
- DOC/DOCX
- XLS/XLSX
- PPT/PPTX
- MP3
- MP4
- AVI
- EXE
- DLL

You can specify multiple file types by separating them with commas.

### Timeline Generation

The timeline feature creates a chronological record of file system events:

```bash
ntfsanalyze -timeline -start 2023-01-01 -end 2023-12-31 -events "creation,modification,deletion" -output ./timeline_output -device /dev/sda1
```

This will generate a timeline of file creation, modification, and deletion events between January 1, 2023, and December 31, 2023, and save it to the specified output directory.

### Security Analysis

The security analysis feature allows you to examine the security descriptors of files:

```bash
ntfsanalyze -security -secfile "path/to/file.txt" -device /dev/sda1
```

This will display information about the file's owner, group, and access control lists (ACLs).

## Performance Considerations

### Large Volumes

When working with large volumes, consider the following:

1. **Memory Usage**: The parser is designed to use chunked reading to minimize memory usage. However, operations like file listing and timeline generation may still require significant memory for large volumes.

2. **Progress Reporting**: For long-running operations, the tool provides progress reporting to give feedback on the operation's status.

3. **Cancellation**: Long-running operations can be cancelled by pressing Ctrl+C.

4. **Buffer Size**: You can adjust the buffer size for better performance using the `-buffer` option. For example:
   ```bash
   ntfsanalyze -carve -buffer 8388608 -device /dev/sda1
   ```
   This sets the buffer size to 8MB (8388608 bytes) for improved I/O performance.

### Split Files

The parser supports split image files (e.g., .001, .002, etc.). When working with split files:

1. Provide the path to the first file in the sequence (e.g., `image.001`).
2. The parser will automatically detect and open all related files.
3. Operations will work seamlessly across file boundaries.

## Troubleshooting

### Common Issues

1. **Permission Denied**: When accessing physical drives, you may need elevated privileges:
   - On Windows: Run the command prompt as Administrator
   - On Linux/macOS: Use `sudo` before the command

2. **File Not Found**: Ensure the path to the NTFS volume or image file is correct.

3. **Not an NTFS Volume**: The parser only works with NTFS file systems. Verify that the target is an NTFS volume.

4. **Memory Issues**: For very large volumes, you may need to increase the available memory or use more targeted operations.

### Error Messages

- **"Error opening volume"**: Check if the path is correct and if you have the necessary permissions.
- **"Not an NTFS volume"**: The specified device or file is not an NTFS volume.
- **"Invalid MFT record"**: The Master File Table (MFT) record is corrupted or invalid.
- **"Operation cancelled"**: The operation was cancelled by the user (Ctrl+C).

## Limitations

- The parser currently only supports NTFS versions 3.0 and above.
- Some advanced NTFS features like encryption may not be fully supported.
- Performance may degrade with extremely large volumes (>2TB).
- The security descriptor parsing is limited to basic ACL interpretation.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 