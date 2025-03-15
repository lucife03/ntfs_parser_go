package ntfs

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scanner handles file scanning operations
type Scanner struct {
	volume *NTFSVolume
	opts   *ScanOptions
	// Add cancellation support
	cancelChan chan struct{}
}

// ScanOptions defines options for scanning
type ScanOptions struct {
	MaxThreads     int  // Maximum number of worker threads
	IncludeSystem  bool // Include system files in results
	MaxResults     int  // Maximum number of results to return (0 for unlimited)
	IncludeDeleted bool // Include deleted files in results
	// Add buffer size option for better performance
	BufferSize int // Size of buffer for reading data (default 1MB)
	// Add progress callback
	ProgressCallback func(processed, total int64, status string)
}

// NewScanner creates a new scanner instance
func NewScanner(volume *NTFSVolume) *Scanner {
	return &Scanner{
		volume: volume,
		opts: &ScanOptions{
			MaxThreads:       runtime.NumCPU() * 2,
			IncludeSystem:    false,
			MaxResults:       0,
			IncludeDeleted:   false,
			BufferSize:       1024 * 1024, // Default 1MB buffer
			ProgressCallback: nil,
		},
		cancelChan: make(chan struct{}),
	}
}

// SetProgressCallback sets a callback function for progress reporting
func (s *Scanner) SetProgressCallback(callback func(processed, total int64, status string)) {
	s.opts.ProgressCallback = callback
}

// Cancel cancels any ongoing operations
func (s *Scanner) Cancel() {
	select {
	case s.cancelChan <- struct{}{}:
	default:
		// Channel already has a value, no need to send again
	}
}

// reportProgress reports progress if a callback is set
func (s *Scanner) reportProgress(processed, total int64, status string) {
	if s.opts.ProgressCallback != nil {
		s.opts.ProgressCallback(processed, total, status)
	}
}

// isCancelled checks if the operation has been cancelled
func (s *Scanner) isCancelled() bool {
	select {
	case <-s.cancelChan:
		return true
	default:
		return false
	}
}

// ListFiles lists all files in the volume
func (s *Scanner) ListFiles(includeDeleted bool) ([]*FileInfo, error) {
	s.opts.IncludeDeleted = includeDeleted

	// Reset cancellation channel
	s.cancelChan = make(chan struct{})

	var (
		results    = make([]*FileInfo, 0)
		resultsMux sync.Mutex
		wg         sync.WaitGroup
		errors     = make([]error, 0)
		errorsMux  sync.Mutex
		processed  atomic.Int64
		total      int64 = 1000 // Initial scan size
		dirMap           = make(map[string][]*FileInfo)
		dirMapMux  sync.Mutex
	)

	// Create work channels with larger buffer for better performance
	jobs := make(chan uint64, s.opts.MaxThreads*10)
	done := make(chan bool)

	// Progress reporting goroutine
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(1 * time.Second):
				s.reportProgress(processed.Load(), total, fmt.Sprintf("Processed %d of %d MFT records... Found %d files",
					processed.Load(), total, len(results)))
			}
		}
	}()

	// Start worker goroutines
	for i := 0; i < s.opts.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for recordIndex := range jobs {
				// Check for cancellation
				if s.isCancelled() {
					return
				}

				record, err := s.volume.GetMFTRecord(recordIndex)
				if err != nil {
					if !strings.Contains(err.Error(), "invalid MFT record signature") &&
						!strings.Contains(err.Error(), "failed to apply fixups") {
						// Only log serious errors
						errorsMux.Lock()
						errors = append(errors, fmt.Errorf("error reading record %d: %v", recordIndex, err))
						errorsMux.Unlock()
					}
					processed.Add(1)
					continue
				}

				fileRecord, err := ParseMFTRecord(record)
				if err != nil {
					processed.Add(1)
					continue // Skip invalid records
				}

				info := getFileInfo(fileRecord, recordIndex, s.volume)
				if info == nil {
					processed.Add(1)
					continue
				}

				// Apply filters
				if !s.shouldIncludeFile(info) {
					processed.Add(1)
					continue
				}

				// Group by directory
				dirMapMux.Lock()
				dir := filepath.Dir(info.Path)
				if dir == "" {
					dir = "/"
				}
				dirMap[dir] = append(dirMap[dir], info)
				dirMapMux.Unlock()

				resultsMux.Lock()
				results = append(results, info)
				if s.opts.MaxResults > 0 && len(results) >= s.opts.MaxResults {
					close(done)
					resultsMux.Unlock()
					return
				}
				resultsMux.Unlock()
				processed.Add(1)
			}
		}()
	}

	// Send work to workers
	go func() {
		for i := uint64(0); i < 1000; i++ {
			// Check for cancellation
			if s.isCancelled() {
				close(jobs)
				return
			}

			select {
			case <-done:
				close(jobs)
				return
			case jobs <- i:
			}
		}
		close(jobs)
	}()

	// Wait for workers to finish
	wg.Wait()
	close(done)

	// Final progress report
	s.reportProgress(processed.Load(), total, fmt.Sprintf("Scan complete. Found %d files.", len(results)))

	// Report errors if any
	if len(errors) > 0 {
		fmt.Printf("\nEncountered %d serious errors during processing. First few errors:\n", len(errors))
		for i := 0; i < min(3, len(errors)); i++ {
			fmt.Printf("- %v\n", errors[i])
		}
		if len(errors) > 3 {
			fmt.Printf("- ... and %d more errors\n", len(errors)-3)
		}
	}

	// Print results grouped by directory
	fmt.Println("\nFiles by directory:")
	dirs := make([]string, 0, len(dirMap))
	for dir := range dirMap {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	for _, dir := range dirs {
		fmt.Printf("\n[Directory] %s\n", dir)
		files := dirMap[dir]
		sort.Slice(files, func(i, j int) bool {
			return files[i].Name < files[j].Name
		})
		for _, file := range files {
			status := "Normal"
			if file.IsDeleted() {
				status = "Deleted"
			}
			size := formatSize(file.Size)
			fmt.Printf("[%s] %s (%s)\n", status, file.Name, size)
		}
	}

	return results, nil
}

// formatSize converts bytes to human readable format
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

// ExtractFile extracts the contents of a file with optimized buffering
func (s *Scanner) ExtractFile(info *FileInfo) ([]byte, error) {
	if info == nil {
		return nil, fmt.Errorf("nil file info")
	}

	// Find the $DATA attribute
	var dataAttr *Attribute
	for i := range info.AttrList {
		if info.AttrList[i].Type == ATTR_DATA && info.AttrList[i].Name == "" {
			dataAttr = &info.AttrList[i]
			break
		}
	}

	if dataAttr == nil {
		return nil, fmt.Errorf("no data attribute found")
	}

	// Handle resident data
	if dataAttr.Resident {
		return dataAttr.Data, nil
	}

	// Handle non-resident data
	if dataAttr.NonResident == nil {
		return nil, fmt.Errorf("invalid non-resident attribute")
	}

	// Parse data runs
	runs, err := parseDataRuns(dataAttr.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data runs: %v", err)
	}

	// Read data from runs with optimized buffering
	data := make([]byte, dataAttr.NonResident.RealSize)
	offset := int64(0)

	// Use a larger buffer for reading clusters
	bufferSize := s.opts.BufferSize
	if bufferSize <= 0 {
		bufferSize = 1024 * 1024 // Default to 1MB if not set
	}

	for _, run := range runs {
		// Check for cancellation
		if s.isCancelled() {
			return nil, fmt.Errorf("operation cancelled")
		}

		if run.IsHole {
			// Fill sparse region with zeros
			for i := int64(0); i < int64(run.ClusterCount*uint64(s.volume.clusterSize)); i++ {
				if offset < int64(dataAttr.NonResident.RealSize) {
					data[offset] = 0
					offset++
				}
			}
			continue
		}

		// Calculate total bytes to read
		bytesToRead := int64(run.ClusterCount * uint64(s.volume.clusterSize))
		startOffset := int64(run.StartCluster) * int64(s.volume.clusterSize)

		// Read in chunks for better performance
		for bytesRead := int64(0); bytesRead < bytesToRead; {
			// Check for cancellation
			if s.isCancelled() {
				return nil, fmt.Errorf("operation cancelled")
			}

			// Calculate chunk size
			chunkSize := int64(bufferSize)
			if bytesRead+chunkSize > bytesToRead {
				chunkSize = bytesToRead - bytesRead
			}

			// Read chunk
			chunk := make([]byte, chunkSize)
			_, err := s.volume.readAt(chunk, startOffset+bytesRead)
			if err != nil {
				return nil, fmt.Errorf("failed to read cluster data: %v", err)
			}

			// Copy to output buffer
			for i := int64(0); i < chunkSize && offset < int64(dataAttr.NonResident.RealSize); i++ {
				data[offset] = chunk[i]
				offset++
			}

			bytesRead += chunkSize

			// Report progress
			s.reportProgress(offset, int64(dataAttr.NonResident.RealSize),
				fmt.Sprintf("Reading file data: %d%%", int(float64(offset)*100/float64(dataAttr.NonResident.RealSize))))
		}
	}

	return data[:dataAttr.NonResident.RealSize], nil
}

// ExtractAllFiles extracts all files to the specified directory
func (s *Scanner) ExtractAllFiles(pattern string) ([]*ExtractedFile, error) {
	files, err := s.ListFiles(false)
	if err != nil {
		return nil, err
	}

	var (
		results    = make([]*ExtractedFile, 0)
		resultsMux sync.Mutex
		wg         sync.WaitGroup
		errors     = make([]error, 0)
		errorsMux  sync.Mutex
	)

	// Create work channels
	jobs := make(chan *FileInfo, s.opts.MaxThreads)

	// Start worker goroutines
	for i := 0; i < s.opts.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				data, err := s.ExtractFile(file)
				if err != nil {
					errorsMux.Lock()
					errors = append(errors, fmt.Errorf("error extracting %s: %v", file.Name, err))
					errorsMux.Unlock()
					continue
				}

				resultsMux.Lock()
				results = append(results, &ExtractedFile{
					Info:    file,
					Content: data,
				})
				resultsMux.Unlock()
			}
		}()
	}

	// Send work to workers
	go func() {
		for _, file := range files {
			jobs <- file
		}
		close(jobs)
	}()

	// Wait for workers to finish
	wg.Wait()

	// Report errors if any
	if len(errors) > 0 {
		fmt.Printf("\nEncountered %d errors during extraction. First few errors:\n", len(errors))
		for i := 0; i < min(3, len(errors)); i++ {
			fmt.Printf("- %v\n", errors[i])
		}
		if len(errors) > 3 {
			fmt.Printf("- ... and %d more errors\n", len(errors)-3)
		}
	}

	return results, nil
}

// SearchFiles searches for files matching the pattern and optionally their content
func (s *Scanner) SearchFiles(pattern string, contentPattern string) ([]*FileInfo, error) {
	files, err := s.ListFiles(false)
	if err != nil {
		return nil, err
	}

	if contentPattern == "" {
		return files, nil
	}

	var (
		results    = make([]*FileInfo, 0)
		resultsMux sync.Mutex
		wg         sync.WaitGroup
		errors     = make([]error, 0)
		errorsMux  sync.Mutex
	)

	// Create work channels
	jobs := make(chan *FileInfo, s.opts.MaxThreads)

	// Start worker goroutines
	for i := 0; i < s.opts.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				data, err := s.ExtractFile(file)
				if err != nil {
					errorsMux.Lock()
					errors = append(errors, fmt.Errorf("error searching %s: %v", file.Name, err))
					errorsMux.Unlock()
					continue
				}

				// Simple string search in content
				if string(data) != contentPattern {
					continue
				}

				resultsMux.Lock()
				results = append(results, file)
				resultsMux.Unlock()
			}
		}()
	}

	// Send work to workers
	go func() {
		for _, file := range files {
			jobs <- file
		}
		close(jobs)
	}()

	// Wait for workers to finish
	wg.Wait()

	return results, nil
}

// ListDeletedFiles returns only deleted files
func (s *Scanner) ListDeletedFiles() ([]*FileInfo, error) {
	return s.ListFiles(true)
}

// shouldIncludeFile checks if a file should be included in results
func (s *Scanner) shouldIncludeFile(info *FileInfo) bool {
	if info == nil || info.Name == "" {
		return false
	}

	// Skip system files unless explicitly requested
	if !s.opts.IncludeSystem && isSystemFile(info.Name) {
		return false
	}

	// Check deletion status
	if info.IsDeleted() && !s.opts.IncludeDeleted {
		return false
	}

	return true
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isSystemFile(name string) bool {
	if len(name) > 0 && name[0] == '$' {
		return true
	}
	return false
}

// getFileInfo creates a FileInfo from a FileRecord
func getFileInfo(record *FileRecord, recordNumber uint64, volume *NTFSVolume) *FileInfo {
	if record == nil {
		return nil
	}

	info := &FileInfo{
		RecordNumber: recordNumber,
		IsDir:        record.IsDirectory,
		Deleted:      record.IsDeleted,
		AttrList:     record.Attributes,
		Path:         "",
		volume:       volume,
	}

	// Extract file name and timestamps from $FILE_NAME attribute
	for _, attr := range record.Attributes {
		if attr.Type == ATTR_FILE_NAME && attr.Resident {
			if len(attr.Data) < 66 { // Minimum size for $FILE_NAME
				continue
			}

			// Get name length (in UTF-16 characters)
			nameLength := attr.Data[64]
			if len(attr.Data) < 66+int(nameLength)*2 {
				continue
			}

			// Extract timestamps
			info.CreationTime = decodeWindowsTime(binary.LittleEndian.Uint64(attr.Data[8:16]))
			info.ModifiedTime = decodeWindowsTime(binary.LittleEndian.Uint64(attr.Data[16:24]))
			info.MFTModifiedTime = decodeWindowsTime(binary.LittleEndian.Uint64(attr.Data[24:32]))
			info.AccessTime = decodeWindowsTime(binary.LittleEndian.Uint64(attr.Data[32:40]))

			// Extract file name (UTF-16 encoded)
			nameBytes := attr.Data[66 : 66+nameLength*2]
			info.Name = decodeUTF16(nameBytes)

			// Get file size from the same attribute
			info.Size = int64(binary.LittleEndian.Uint64(attr.Data[48:56]))          // Real size
			info.AllocatedSize = int64(binary.LittleEndian.Uint64(attr.Data[40:48])) // Allocated size

			// Once we find a valid $FILE_NAME attribute, we can break
			break
		}
	}

	// If no valid $FILE_NAME attribute was found, try to get size from $DATA
	if info.Size == 0 {
		for _, attr := range record.Attributes {
			if attr.Type == ATTR_DATA && attr.Name == "" {
				if attr.Resident {
					info.Size = int64(len(attr.Data))
					info.AllocatedSize = info.Size
				} else if attr.NonResident != nil {
					info.Size = int64(attr.NonResident.RealSize)
					info.AllocatedSize = int64(attr.NonResident.AllocatedSize)
				}
				break
			}
		}
	}

	return info
}

// ExtractedFile represents a file and its contents
type ExtractedFile struct {
	Info    *FileInfo
	Content []byte
}

// SetIncludeDeleted sets whether to include deleted files in the scan
func (s *Scanner) SetIncludeDeleted(include bool) {
	s.opts.IncludeDeleted = include
}

// GenerateTimeline generates a timeline of filesystem events
func (s *Scanner) GenerateTimeline(opts TimelineOptions) ([]TimelineEntry, error) {
	// Get all files including deleted if requested
	files, err := s.ListFiles(opts.IncludeDeleted)
	if err != nil {
		return nil, fmt.Errorf("error listing files: %v", err)
	}

	var entries []TimelineEntry

	// Process each file
	for _, file := range files {
		// Skip if outside time range
		if !opts.StartTime.IsZero() && file.CreationTime.Before(opts.StartTime) {
			continue
		}
		if !opts.EndTime.IsZero() && file.CreationTime.After(opts.EndTime) {
			continue
		}

		// Add events based on requested types
		for _, eventType := range opts.EventTypes {
			switch eventType {
			case "creation":
				entries = append(entries, TimelineEntry{
					Timestamp: file.CreationTime,
					EventType: "Creation",
					File:      file,
					Details:   "File created",
				})
			case "modification":
				entries = append(entries, TimelineEntry{
					Timestamp: file.ModifiedTime,
					EventType: "Modified",
					File:      file,
					Details:   "Content modified",
				})
			case "access":
				entries = append(entries, TimelineEntry{
					Timestamp: file.AccessTime,
					EventType: "Access",
					File:      file,
					Details:   "File accessed",
				})
			case "mft":
				entries = append(entries, TimelineEntry{
					Timestamp: file.MFTModifiedTime,
					EventType: "MFT Update",
					File:      file,
					Details:   "MFT entry modified",
				})
			case "deletion":
				if file.IsDeleted() {
					entries = append(entries, TimelineEntry{
						Timestamp: file.ModifiedTime, // Using modified time as deletion time
						EventType: "Deletion",
						File:      file,
						Details:   "File deleted",
					})
				}
			}
		}
	}

	// Sort entries by timestamp
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	return entries, nil
}

// ExtractMetadata extracts detailed metadata from a file
func (s *Scanner) ExtractMetadata(file *FileInfo) (*FileMetadata, error) {
	if file == nil {
		return nil, fmt.Errorf("nil file info")
	}

	metadata := &FileMetadata{
		Signatures:    make([]string, 0),
		ExtendedAttrs: make(map[string]string),
		Fragments:     make([]Fragment, 0),
		IsCompressed:  false,
		IsEncrypted:   false,
	}

	// Get file content for signature analysis
	content, err := s.ExtractFile(file)
	if err == nil && len(content) > 0 {
		// Calculate SHA256 hash
		hash := sha256.New()
		hash.Write(content)
		metadata.Signatures = append(metadata.Signatures, fmt.Sprintf("SHA256:%x", hash.Sum(nil)))

		// Detect MIME type
		size := len(content)
		if size > 512 {
			size = 512
		}
		metadata.MIMEType = http.DetectContentType(content[:size])

		// Calculate entropy
		if len(content) > 0 {
			// Calculate byte frequency
			freq := make(map[byte]int)
			for _, b := range content {
				freq[b]++
			}

			// Calculate entropy
			entropy := 0.0
			size := float64(len(content))
			for _, count := range freq {
				p := float64(count) / size
				entropy -= p * math.Log2(p)
			}
			metadata.Entropy = entropy
		}
	}

	// Process attributes
	attrs := file.Attributes()
	for _, attr := range attrs {
		switch attr.Type {
		case ATTR_STANDARD_INFORMATION:
			metadata.IsCompressed = (attr.Flags & 0x0800) != 0
			metadata.IsEncrypted = (attr.Flags & 0x4000) != 0

		case ATTR_EA:
			// Extract extended attributes
			if attr.Resident {
				parseExtendedAttributes(attr.Data, metadata.ExtendedAttrs)
			}

		case ATTR_DATA:
			// Collect fragment information for non-resident data
			if !attr.Resident && attr.NonResident != nil {
				runs, err := parseDataRuns(attr.Data)
				if err != nil {
					continue
				}

				// Add fragment information
				for _, run := range runs {
					if !run.IsHole {
						metadata.Fragments = append(metadata.Fragments, Fragment{
							Offset: int64(run.StartCluster) * int64(s.volume.clusterSize),
							Size:   int64(run.ClusterCount) * int64(s.volume.clusterSize),
							Type:   "Data",
						})
					}
				}
			}
		}
	}

	return metadata, nil
}

func parseExtendedAttributes(data []byte, attrs map[string]string) {
	offset := 0
	for offset < len(data) {
		if offset+8 > len(data) {
			break
		}

		// Parse EA header
		nextEntry := binary.LittleEndian.Uint32(data[offset:])
		nameLen := data[offset+4]
		valueLen := binary.LittleEndian.Uint16(data[offset+5:])
		// Note: flags byte at offset+7 is reserved for future use

		offset += 8

		if offset+int(nameLen) > len(data) {
			break
		}

		// Get name
		name := string(data[offset : offset+int(nameLen)])
		offset += int(nameLen)

		if offset+int(valueLen) > len(data) {
			break
		}

		// Get value
		value := string(data[offset : offset+int(valueLen)])
		offset += int(valueLen)

		// Store attribute
		attrs[name] = value

		// Move to next entry if needed
		if nextEntry == 0 {
			break
		}
		offset = int(nextEntry)
	}
}

// PrintMetadata prints formatted metadata information
func (s *Scanner) PrintMetadata(file *FileInfo) error {
	metadata, err := s.ExtractMetadata(file)
	if err != nil {
		return err
	}

	fmt.Printf("\nMetadata for %s:\n", file.Name)
	fmt.Printf("====================%s\n", strings.Repeat("=", len(file.Name)))
	fmt.Printf("Basic Information:\n")
	fmt.Printf("  Size: %s (Allocated: %s)\n", formatSize(file.Size), formatSize(file.AllocatedSize))
	fmt.Printf("  Type: %s\n", metadata.MIMEType)
	fmt.Printf("  Created: %s\n", file.CreationTime.Format(time.RFC3339))
	fmt.Printf("  Modified: %s\n", file.ModifiedTime.Format(time.RFC3339))
	fmt.Printf("  Accessed: %s\n", file.AccessTime.Format(time.RFC3339))
	fmt.Printf("  MFT Modified: %s\n", file.MFTModifiedTime.Format(time.RFC3339))

	fmt.Printf("\nFile Attributes:\n")
	fmt.Printf("  Is Directory: %v\n", file.IsDirectory())
	fmt.Printf("  Is Deleted: %v\n", file.IsDeleted())
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

	return nil
}
