package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/ntfs_parser/pkg/ntfs"
)

// Global variables for cancellation
var (
	cancelRequested bool
)

func main() {
	var (
		devicePath     string
		outputPath     string
		searchPattern  string
		listOnly       bool
		includeDeleted bool
		recursive      bool
		timeline       bool
		startTime      string
		endTime        string
		timelineTypes  string
		metadata       string
		carve          bool
		carveTypes     string
		journal        bool
		journalStart   int64
		journalMax     int
		security       bool
		securityFile   string
		help           bool
		bufferSize     int
	)

	// Parse command line arguments
	flag.StringVar(&devicePath, "device", "", "Path to NTFS volume or image file")
	flag.StringVar(&outputPath, "output", "", "Output directory for recovered files")
	flag.StringVar(&searchPattern, "pattern", "", "Search pattern (e.g., '*.txt')")
	flag.BoolVar(&listOnly, "list", false, "Only list files, don't recover")
	flag.BoolVar(&includeDeleted, "deleted", false, "Include deleted files")
	flag.BoolVar(&recursive, "recursive", false, "Recursive search in subdirectories")
	flag.BoolVar(&timeline, "timeline", false, "Generate filesystem timeline")
	flag.StringVar(&startTime, "start", "", "Timeline start time (YYYY-MM-DD)")
	flag.StringVar(&endTime, "end", "", "Timeline end time (YYYY-MM-DD)")
	flag.StringVar(&timelineTypes, "events", "all", "Event types to include (comma-separated)")
	flag.StringVar(&metadata, "metadata", "", "Extract metadata for specific file")
	flag.BoolVar(&carve, "carve", false, "Perform file carving")
	flag.StringVar(&carveTypes, "carvetypes", "", "File types to carve (comma-separated: JPEG,PNG,PDF)")
	flag.BoolVar(&journal, "journal", false, "Parse USN journal")
	flag.Int64Var(&journalStart, "journalstart", 0, "Starting USN for journal parsing")
	flag.IntVar(&journalMax, "journalmax", 1000, "Maximum number of journal entries to return")
	flag.BoolVar(&security, "security", false, "Analyze file security")
	flag.StringVar(&securityFile, "secfile", "", "File to analyze security for")
	flag.BoolVar(&help, "help", false, "Show help information")
	flag.IntVar(&bufferSize, "buffer", 4*1024*1024, "Buffer size for operations (in bytes)")

	flag.Parse()

	// Show help if requested
	if help {
		showHelp()
		return
	}

	// Check required parameters
	if devicePath == "" {
		fmt.Println("Error: device path is required")
		flag.Usage()
		os.Exit(1)
	}

	// Set up signal handling for cancellation
	setupCancellationHandler()

	// Open the NTFS volume
	fmt.Printf("Opening NTFS volume: %s\n", devicePath)
	volume, err := ntfs.NewNTFSVolume(devicePath)
	if err != nil {
		fmt.Printf("Error opening volume: %v\n", err)
		os.Exit(1)
	}
	defer volume.Close()

	// Create output directory if needed
	if outputPath != "" {
		if err := os.MkdirAll(outputPath, 0755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			os.Exit(1)
		}
	}

	// Process commands
	if listOnly {
		listFiles(volume, includeDeleted, searchPattern, recursive)
	} else if metadata != "" {
		extractMetadata(volume, metadata)
	} else if timeline {
		generateTimeline(volume, startTime, endTime, timelineTypes, outputPath)
	} else if carve {
		carveFiles(volume, carveTypes, outputPath, bufferSize)
	} else if journal {
		parseJournal(volume, journalStart, journalMax)
	} else if security {
		analyzeSecurity(volume, securityFile)
	} else {
		fmt.Println("No operation specified. Use -list, -metadata, -timeline, -carve, -journal, or -security.")
		fmt.Println("Use -help for more information.")
	}
}

// showHelp displays detailed help information about the tool
func showHelp() {
	fmt.Println("NTFS Analyzer - A forensic tool for NTFS file systems")
	fmt.Println("=====================================================")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("  ntfsanalyze [options]")
	fmt.Println()
	fmt.Println("BASIC OPTIONS:")
	fmt.Println("  -device string      Path to NTFS volume or image file (required)")
	fmt.Println("  -output string      Output directory for recovered files")
	fmt.Println("  -help               Show this help information")
	fmt.Println("  -buffer int         Buffer size for operations in bytes (default: 4MB)")
	fmt.Println()
	fmt.Println("FILE LISTING OPTIONS:")
	fmt.Println("  -list               List files in the volume")
	fmt.Println("  -pattern string     Search pattern (e.g., '*.txt')")
	fmt.Println("  -deleted            Include deleted files")
	fmt.Println("  -recursive          Recursive search in subdirectories")
	fmt.Println()
	fmt.Println("METADATA OPTIONS:")
	fmt.Println("  -metadata string    Extract metadata for specific file")
	fmt.Println()
	fmt.Println("TIMELINE OPTIONS:")
	fmt.Println("  -timeline           Generate filesystem timeline")
	fmt.Println("  -start string       Timeline start time (YYYY-MM-DD)")
	fmt.Println("  -end string         Timeline end time (YYYY-MM-DD)")
	fmt.Println("  -events string      Event types to include (comma-separated, default: all)")
	fmt.Println("                      Available types: creation,modification,access,mft,deletion")
	fmt.Println()
	fmt.Println("FILE CARVING OPTIONS:")
	fmt.Println("  -carve              Perform file carving")
	fmt.Println("  -carvetypes string  File types to carve (comma-separated)")
	fmt.Println("                      Available types: JPEG,PNG,GIF,PDF,ZIP,DOC,XLS,PPT")
	fmt.Println()
	fmt.Println("JOURNAL OPTIONS:")
	fmt.Println("  -journal            Parse USN journal")
	fmt.Println("  -journalstart int   Starting USN for journal parsing")
	fmt.Println("  -journalmax int     Maximum number of journal entries to return (default: 1000)")
	fmt.Println()
	fmt.Println("SECURITY OPTIONS:")
	fmt.Println("  -security           Analyze file security")
	fmt.Println("  -secfile string     File to analyze security for")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  List all files:")
	fmt.Println("    ntfsanalyze -device /dev/sda1 -list")
	fmt.Println()
	fmt.Println("  List deleted files:")
	fmt.Println("    ntfsanalyze -device image.dd -list -deleted")
	fmt.Println()
	fmt.Println("  Extract metadata for a file:")
	fmt.Println("    ntfsanalyze -device /dev/sda1 -metadata \"file.txt\"")
	fmt.Println()
	fmt.Println("  Generate timeline:")
	fmt.Println("    ntfsanalyze -device image.dd -timeline -output timeline_output")
	fmt.Println()
	fmt.Println("  Carve files:")
	fmt.Println("    ntfsanalyze -device image.dd -carve -carvetypes \"JPEG,PDF\" -output carved_files")
	fmt.Println()
	fmt.Println("  Analyze file security:")
	fmt.Println("    ntfsanalyze -device /dev/sda1 -security -secfile \"important.docx\"")
}

// setupCancellationHandler sets up a handler for Ctrl+C to cancel operations
func setupCancellationHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		<-c
		fmt.Println("\nCancellation requested. Stopping operations...")
		cancelRequested = true
	}()
}

// progressCallback is a generic progress callback function
func progressCallback(processed, total int64, status string) {
	// Clear the line and print the progress
	fmt.Printf("\r%-70s", "")
	fmt.Printf("\r%s - %.1f%% complete", status, float64(processed)/float64(total)*100)
}

// listFiles lists files in the volume
func listFiles(volume *ntfs.NTFSVolume, includeDeleted bool, pattern string, recursive bool) {
	fmt.Println("Listing files...")

	// Create scanner with progress reporting
	scanner := ntfs.NewScanner(volume)
	scanner.SetProgressCallback(progressCallback)

	// Start listing files
	files, err := scanner.ListFiles(includeDeleted)
	if err != nil {
		fmt.Printf("\nError listing files: %v\n", err)
		return
	}

	// Print debug information for the first 10 files found
	fmt.Println("\nFirst 10 files found (debug):")
	for i, file := range files {
		if i >= 10 {
			break
		}
		fmt.Printf("Debug [%d]: %s (RecordNum: %d, Size: %d, IsDir: %v, IsDeleted: %v)\n",
			i, file.Name, file.RecordNumber, file.Size, file.IsDirectory(), file.IsDeleted())
	}

	fmt.Printf("\nFound %d files\n", len(files))

	// Filter by pattern if specified
	if pattern != "" {
		filtered := make([]*ntfs.FileInfo, 0)
		for _, file := range files {
			matched, err := filepath.Match(pattern, file.Name)
			if err != nil {
				fmt.Printf("Error matching pattern: %v\n", err)
				continue
			}
			if matched {
				filtered = append(filtered, file)
			}
		}
		fmt.Printf("Filtered to %d files matching pattern '%s'\n", len(filtered), pattern)
		files = filtered
	}

	// Print files
	for _, file := range files {
		status := "Normal"
		if file.IsDeleted() {
			status = "Deleted"
		}
		fmt.Printf("[%s] %s (%s)\n", status, file.Name, formatSize(file.Size))
	}
}

// extractMetadata extracts and displays metadata for a specific file
func extractMetadata(volume *ntfs.NTFSVolume, filePath string) {
	fmt.Printf("Extracting metadata for: %s\n", filePath)

	// Create scanner
	scanner := ntfs.NewScanner(volume)

	// List files to find the target
	files, err := scanner.ListFiles(true)
	if err != nil {
		fmt.Printf("Error listing files: %v\n", err)
		return
	}

	// Find the file
	var targetFile *ntfs.FileInfo
	for _, file := range files {
		if strings.EqualFold(file.Name, filePath) || strings.EqualFold(file.Path, filePath) {
			targetFile = file
			break
		}
	}

	if targetFile == nil {
		fmt.Printf("File not found: %s\n", filePath)
		return
	}

	// Extract metadata
	metadata, err := scanner.ExtractMetadata(targetFile)
	if err != nil {
		fmt.Printf("Error extracting metadata: %v\n", err)
		return
	}

	// Print metadata
	fmt.Printf("\nMetadata for %s:\n", targetFile.Name)
	fmt.Printf("====================%s\n", strings.Repeat("=", len(targetFile.Name)))
	fmt.Printf("Basic Information:\n")
	fmt.Printf("  Size: %s (Allocated: %s)\n", formatSize(targetFile.Size), formatSize(targetFile.AllocatedSize))
	fmt.Printf("  Type: %s\n", metadata.MIMEType)
	fmt.Printf("  Created: %s\n", targetFile.CreationTime.Format(time.RFC3339))
	fmt.Printf("  Modified: %s\n", targetFile.ModifiedTime.Format(time.RFC3339))
	fmt.Printf("  Accessed: %s\n", targetFile.AccessTime.Format(time.RFC3339))
	fmt.Printf("  MFT Modified: %s\n", targetFile.MFTModifiedTime.Format(time.RFC3339))

	fmt.Printf("\nFile Attributes:\n")
	fmt.Printf("  Is Directory: %v\n", targetFile.IsDirectory())
	fmt.Printf("  Is Deleted: %v\n", targetFile.IsDeleted())
	fmt.Printf("  Is Compressed: %v\n", metadata.IsCompressed)
	fmt.Printf("  Is Encrypted: %v\n", metadata.IsEncrypted)
	fmt.Printf("  Entropy: %.2f\n", metadata.Entropy)

	if len(metadata.Signatures) > 0 {
		fmt.Printf("\nSignatures:\n")
		for _, sig := range metadata.Signatures {
			fmt.Printf("  %s\n", sig)
		}
	}

	if len(metadata.ExtendedAttrs) > 0 {
		fmt.Printf("\nExtended Attributes:\n")
		for name, value := range metadata.ExtendedAttrs {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}

	if len(metadata.Fragments) > 0 {
		fmt.Printf("\nFile Fragments:\n")
		for i, frag := range metadata.Fragments {
			fmt.Printf("  Fragment %d: Offset=%d, Size=%s\n",
				i+1, frag.Offset, formatSize(frag.Size))
		}
	}
}

// generateTimeline generates a filesystem timeline
func generateTimeline(volume *ntfs.NTFSVolume, startTimeStr, endTimeStr, eventTypesStr, outputPath string) {
	fmt.Println("Generating timeline...")

	// Parse time range
	var startTime, endTime time.Time
	var err error

	if startTimeStr != "" {
		startTime, err = time.Parse("2006-01-02", startTimeStr)
		if err != nil {
			fmt.Printf("Error parsing start time: %v\n", err)
			return
		}
	}

	if endTimeStr != "" {
		endTime, err = time.Parse("2006-01-02", endTimeStr)
		if err != nil {
			fmt.Printf("Error parsing end time: %v\n", err)
			return
		}
		// Set to end of day
		endTime = endTime.Add(24*time.Hour - 1*time.Second)
	}

	// Parse event types
	var eventTypes []string
	if eventTypesStr == "all" {
		eventTypes = []string{"creation", "modification", "access", "mft", "deletion"}
	} else {
		eventTypes = strings.Split(eventTypesStr, ",")
		for i, t := range eventTypes {
			eventTypes[i] = strings.TrimSpace(t)
		}
	}

	// Create timeline options
	opts := &ntfs.TimelineOptions{
		StartTime:      startTime,
		EndTime:        endTime,
		IncludeDeleted: true,
		EventTypes:     eventTypes,
	}

	// Create timeline generator with progress reporting
	generator := ntfs.NewTimelineGenerator(volume, opts)
	generator.SetProgressCallback(progressCallback)

	// Generate timeline
	entries, err := generator.GenerateTimeline()
	if err != nil {
		fmt.Printf("\nError generating timeline: %v\n", err)
		return
	}

	fmt.Printf("\nGenerated timeline with %d events\n", len(entries))

	// Print timeline
	fmt.Println("\nTimeline:")
	fmt.Println("=========")

	for i, entry := range entries {
		if i >= 100 {
			fmt.Printf("... and %d more events (use -output to save full timeline)\n", len(entries)-100)
			break
		}

		// Get file name from the File interface
		fileName := entry.File.GetName()
		if entry.File.IsDeleted() {
			fileName += " (Deleted)"
		}

		fmt.Printf("[%s] %s - %s - %s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.EventType,
			fileName,
			entry.Details)
	}

	// Export timeline if output path specified
	if outputPath != "" {
		err := generator.ExportTimeline(entries, "csv", filepath.Join(outputPath, "timeline.csv"))
		if err != nil {
			fmt.Printf("Error exporting timeline: %v\n", err)
		} else {
			fmt.Printf("Timeline exported to %s\n", filepath.Join(outputPath, "timeline.csv"))
		}
	}
}

// carveFiles carves files from the volume
func carveFiles(volume *ntfs.NTFSVolume, carveTypesStr, outputPath string, bufferSize int) {
	fmt.Println("Carving files...")

	// Parse file types
	var fileTypes []string
	if carveTypesStr != "" {
		fileTypes = strings.Split(carveTypesStr, ",")
		for i, t := range fileTypes {
			fileTypes[i] = strings.TrimSpace(t)
		}
	}

	// Create carver options
	opts := &ntfs.CarveOptions{
		OutputDir:   outputPath,
		FileTypes:   fileTypes,
		MaxFileSize: 100 * 1024 * 1024, // 100MB default
		BufferSize:  bufferSize,        // Use specified buffer size
	}

	// Create carver with progress reporting
	carver := ntfs.NewFileCarver(volume, opts)
	carver.SetProgressCallback(progressCallback)

	// Carve files
	carvedFiles, err := carver.CarveFiles()
	if err != nil {
		fmt.Printf("\nError carving files: %v\n", err)
		return
	}

	fmt.Printf("\nCarved %d files to %s\n", len(carvedFiles), outputPath)

	// Print carved files
	if len(carvedFiles) > 0 {
		fmt.Println("\nCarved Files:")
		fmt.Println("============")

		for i, file := range carvedFiles {
			if i >= 20 {
				fmt.Printf("... and %d more files\n", len(carvedFiles)-20)
				break
			}

			fmt.Printf("%s\n", filepath.Base(file))
		}
	}
}

// parseJournal parses the USN journal
func parseJournal(volume *ntfs.NTFSVolume, startUSN int64, maxEntries int) {
	fmt.Println("Parsing USN journal...")

	// This is a placeholder - actual implementation would depend on the journal parsing code
	fmt.Println("USN journal parsing not fully implemented yet")
}

// analyzeSecurity analyzes file security
func analyzeSecurity(volume *ntfs.NTFSVolume, filePath string) {
	fmt.Printf("Analyzing security for: %s\n", filePath)

	// Create scanner
	scanner := ntfs.NewScanner(volume)

	// List files to find the target
	files, err := scanner.ListFiles(true)
	if err != nil {
		fmt.Printf("Error listing files: %v\n", err)
		return
	}

	// Find the file
	var targetFile *ntfs.FileInfo
	for _, file := range files {
		if strings.EqualFold(file.Name, filePath) || strings.EqualFold(file.Path, filePath) {
			targetFile = file
			break
		}
	}

	if targetFile == nil {
		fmt.Printf("File not found: %s\n", filePath)
		return
	}

	// Get security descriptor
	secData, err := targetFile.SecurityDescriptor()
	if err != nil {
		fmt.Printf("Error getting security descriptor: %v\n", err)
		return
	}

	// Create security parser
	secParser := ntfs.NewSecurityParser(volume)

	// Parse security descriptor
	sd, err := secParser.ParseSecurityDescriptor(secData)
	if err != nil {
		fmt.Printf("Error parsing security descriptor: %v\n", err)
		return
	}

	// Print security information
	fmt.Printf("\nSecurity Information for %s:\n", targetFile.Name)
	fmt.Printf("==========================%s\n", strings.Repeat("=", len(targetFile.Name)))

	// Print owner
	if sd.OwnerSID != nil {
		fmt.Printf("Owner: %s\n", sd.OwnerSID.GetSIDString())
	}

	// Print group
	if sd.GroupSID != nil {
		fmt.Printf("Group: %s\n", sd.GroupSID.GetSIDString())
	}

	// Print DACL
	if sd.DACL != nil {
		fmt.Printf("\nDiscretionary Access Control List (DACL):\n")
		fmt.Printf("----------------------------------------\n")

		for i, ace := range sd.DACL.ACEs {
			fmt.Printf("ACE %d:\n", i+1)
			fmt.Printf("  Type: %d\n", ace.Type)
			fmt.Printf("  Flags: %d\n", ace.Flags)
			fmt.Printf("  Access: %s\n", ace.GetPermissionString())
			fmt.Printf("  Trustee: %s\n", ace.SID.GetSIDString())
			fmt.Println()
		}
	}

	// Print SACL if present
	if sd.SACL != nil {
		fmt.Printf("\nSystem Access Control List (SACL):\n")
		fmt.Printf("--------------------------------\n")

		for i, ace := range sd.SACL.ACEs {
			fmt.Printf("ACE %d:\n", i+1)
			fmt.Printf("  Type: %d\n", ace.Type)
			fmt.Printf("  Flags: %d\n", ace.Flags)
			fmt.Printf("  Access: %s\n", ace.GetPermissionString())
			fmt.Printf("  Trustee: %s\n", ace.SID.GetSIDString())
			fmt.Println()
		}
	}
}

// formatSize formats a size in bytes to a human-readable string
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
