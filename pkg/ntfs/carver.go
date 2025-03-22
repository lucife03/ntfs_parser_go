package ntfs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// FileSignature represents a file format signature
type FileSignature struct {
	Name      string   // Format name (e.g., "JPEG", "PDF")
	MIMEType  string   // MIME type
	Headers   [][]byte // File header signatures
	Footers   [][]byte // File footer signatures (if any)
	Extension string   // File extension
	MaxSize   int64    // Maximum expected file size (0 for unlimited)
}

// Common file signatures
var (
	CommonSignatures = []FileSignature{
		{
			Name:      "JPEG",
			MIMEType:  "image/jpeg",
			Headers:   [][]byte{{0xFF, 0xD8, 0xFF}},
			Footers:   [][]byte{{0xFF, 0xD9}},
			Extension: ".jpg",
			MaxSize:   20 * 1024 * 1024, // 20MB
		},
		{
			Name:      "PNG",
			MIMEType:  "image/png",
			Headers:   [][]byte{{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}},
			Footers:   [][]byte{{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}},
			Extension: ".png",
			MaxSize:   20 * 1024 * 1024, // 20MB
		},
		{
			Name:      "PDF",
			MIMEType:  "application/pdf",
			Headers:   [][]byte{{0x25, 0x50, 0x44, 0x46}},
			Footers:   [][]byte{{0x0A, 0x25, 0x25, 0x45, 0x4F, 0x46}},
			Extension: ".pdf",
			MaxSize:   100 * 1024 * 1024, // 100MB
		},
		// Add more signatures as needed
	}
)

// CarvedFile represents a carved file from raw data
type CarvedFile struct {
	Signature   FileSignature
	StartOffset int64
	EndOffset   int64
	Size        int64
	Data        []byte
	IsValid     bool
	Fragments   []Fragment
}

// FileCarver handles file carving operations
type FileCarver struct {
	volume      *NTFSVolume
	signatures  map[string][]byte
	extensions  map[string]string
	maxFileSize int64
	outputDir   string
	// Add cancellation support
	cancelChan chan struct{}
	// Add progress callback
	progressCallback func(current, total int64, status string)
	// Add buffer size for optimized reading
	bufferSize int
}

// CarveOptions defines options for file carving
type CarveOptions struct {
	OutputDir   string   // Directory to save carved files
	FileTypes   []string // File types to carve (e.g., "JPEG", "PNG", "PDF")
	MaxFileSize int64    // Maximum file size to carve (0 for unlimited)
	MaxResults  int      // Maximum number of results (0 for unlimited)
	// Add buffer size option
	BufferSize int // Size of buffer for reading data (default 1MB)
}

// NewFileCarver creates a new file carver
func NewFileCarver(volume *NTFSVolume, opts *CarveOptions) *FileCarver {
	if opts == nil {
		opts = &CarveOptions{
			OutputDir:   "carved_files",
			FileTypes:   []string{"JPEG", "PNG", "PDF"},
			MaxFileSize: 100 * 1024 * 1024, // 100MB default
			MaxResults:  0,
			BufferSize:  1024 * 1024, // 1MB default
		}
	}

	// Create output directory if it doesn't exist
	if opts.OutputDir != "" {
		os.MkdirAll(opts.OutputDir, 0755)
	}

	carver := &FileCarver{
		volume:      volume,
		signatures:  make(map[string][]byte),
		extensions:  make(map[string]string),
		maxFileSize: opts.MaxFileSize,
		outputDir:   opts.OutputDir,
		cancelChan:  make(chan struct{}),
		bufferSize:  opts.BufferSize,
	}

	// Initialize file signatures
	carver.initSignatures(opts.FileTypes)

	return carver
}

// SetProgressCallback sets a callback function for progress reporting
func (c *FileCarver) SetProgressCallback(callback func(current, total int64, status string)) {
	c.progressCallback = callback
}

// Cancel cancels any ongoing carving operation
func (c *FileCarver) Cancel() {
	select {
	case c.cancelChan <- struct{}{}:
	default:
		// Channel already has a value, no need to send again
	}
}

// reportProgress reports progress if a callback is set
func (c *FileCarver) reportProgress(current, total int64, status string) {
	if c.progressCallback != nil {
		c.progressCallback(current, total, status)
	}
}

// isCancelled checks if the operation has been cancelled
func (c *FileCarver) isCancelled() bool {
	select {
	case <-c.cancelChan:
		return true
	default:
		return false
	}
}

// initSignatures initializes file signatures for carving
func (c *FileCarver) initSignatures(types []string) {
	// Common file signatures (magic numbers)
	allSignatures := map[string]struct {
		signature []byte
		extension string
	}{
		"JPEG": {[]byte{0xFF, 0xD8, 0xFF}, ".jpg"},
		"PNG":  {[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, ".png"},
		"GIF":  {[]byte{0x47, 0x49, 0x46, 0x38}, ".gif"},
		"BMP":  {[]byte{0x42, 0x4D}, ".bmp"},
		"PDF":  {[]byte{0x25, 0x50, 0x44, 0x46}, ".pdf"},
		"ZIP":  {[]byte{0x50, 0x4B, 0x03, 0x04}, ".zip"},
		"RAR":  {[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, ".rar"},
		"DOC":  {[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, ".doc"},
		"DOCX": {[]byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00}, ".docx"},
		"XLS":  {[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, ".xls"},
		"XLSX": {[]byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00}, ".xlsx"},
		"PPT":  {[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, ".ppt"},
		"PPTX": {[]byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00}, ".pptx"},
		"MP3":  {[]byte{0x49, 0x44, 0x33}, ".mp3"},
		"MP4":  {[]byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, ".mp4"},
		"AVI":  {[]byte{0x52, 0x49, 0x46, 0x46}, ".avi"},
		"EXE":  {[]byte{0x4D, 0x5A}, ".exe"},
		"DLL":  {[]byte{0x4D, 0x5A}, ".dll"},
	}

	// If no specific types are requested, use all
	if len(types) == 0 {
		for name, sig := range allSignatures {
			c.signatures[name] = sig.signature
			c.extensions[name] = sig.extension
		}
		return
	}

	// Add only requested types
	for _, t := range types {
		t = strings.ToUpper(t)
		if sig, ok := allSignatures[t]; ok {
			c.signatures[t] = sig.signature
			c.extensions[t] = sig.extension
		}
	}
}

// CarveFiles carves files from the volume
func (c *FileCarver) CarveFiles() ([]string, error) {
	// Reset cancellation channel
	c.cancelChan = make(chan struct{})

	var (
		carvedFiles = make([]string, 0)
		mutex       = &sync.Mutex{}
		wg          = &sync.WaitGroup{}
		errors      = make([]error, 0)
		errorMutex  = &sync.Mutex{}
	)

	// Get volume size
	volumeSize := c.volume.volumeSize

	// Use a reasonable chunk size for scanning
	chunkSize := int64(c.bufferSize)
	if chunkSize <= 0 {
		chunkSize = 1024 * 1024 // Default to 1MB
	}

	// Number of chunks to process
	numChunks := (volumeSize + chunkSize - 1) / chunkSize

	// Create a channel for chunks to process
	chunks := make(chan int64, 100)

	// Start worker goroutines
	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Buffer for reading data
			buffer := make([]byte, chunkSize+1024) // Extra space for overlap

			for offset := range chunks {
				// Check for cancellation
				if c.isCancelled() {
					return
				}

				// Calculate actual chunk size (might be smaller at the end)
				actualSize := chunkSize
				if offset+actualSize > volumeSize {
					actualSize = volumeSize - offset
				}

				// Read chunk with some overlap for signatures that might span chunks
				readSize := actualSize
				if offset+readSize+1024 <= volumeSize {
					readSize += 1024 // Add overlap
				}

				// Read the chunk
				n, err := c.volume.readAt(buffer[:readSize], offset)
				if err != nil {
					errorMutex.Lock()
					errors = append(errors, fmt.Errorf("error reading at offset %d: %v", offset, err))
					errorMutex.Unlock()
					continue
				}

				// Process the chunk
				chunk := buffer[:n]
				files, err := c.processChunk(chunk, offset)
				if err != nil {
					errorMutex.Lock()
					errors = append(errors, err)
					errorMutex.Unlock()
					continue
				}

				// Add carved files to the result
				if len(files) > 0 {
					mutex.Lock()
					carvedFiles = append(carvedFiles, files...)
					mutex.Unlock()
				}

				// Report progress
				c.reportProgress(offset+int64(n), volumeSize,
					fmt.Sprintf("Carving files: %.1f%% complete", float64(offset+int64(n))*100/float64(volumeSize)))
			}
		}()
	}

	// Send chunks to workers
	go func() {
		for i := int64(0); i < numChunks; i++ {
			// Check for cancellation
			if c.isCancelled() {
				close(chunks)
				return
			}

			chunks <- i * chunkSize
		}
		close(chunks)
	}()

	// Wait for all workers to finish
	wg.Wait()

	// Report any errors
	if len(errors) > 0 {
		fmt.Printf("Encountered %d errors during carving. First few errors:\n", len(errors))
		for i := 0; i < min(3, len(errors)); i++ {
			fmt.Printf("- %v\n", errors[i])
		}
		if len(errors) > 3 {
			fmt.Printf("- ... and %d more errors\n", len(errors)-3)
		}
	}

	// Final progress report
	c.reportProgress(volumeSize, volumeSize, fmt.Sprintf("Carving complete. Found %d files.", len(carvedFiles)))

	return carvedFiles, nil
}

// processChunk processes a chunk of data for file carving
func (c *FileCarver) processChunk(chunk []byte, baseOffset int64) ([]string, error) {
	carvedFiles := make([]string, 0)

	// Check for cancellation
	if c.isCancelled() {
		return carvedFiles, nil
	}

	// Look for file signatures in the chunk
	for fileType, signature := range c.signatures {
		// Find all occurrences of the signature
		for i := 0; i <= len(chunk)-len(signature); i++ {
			// Check for cancellation periodically
			if i%1000 == 0 && c.isCancelled() {
				return carvedFiles, nil
			}

			if bytes.Equal(chunk[i:i+len(signature)], signature) {
				// Found a signature, try to carve the file
				fileOffset := baseOffset + int64(i)
				fileName, err := c.carveFile(fileType, fileOffset)
				if err != nil {
					// Just log the error and continue
					fmt.Printf("Error carving %s at offset %d: %v\n", fileType, fileOffset, err)
					continue
				}

				if fileName != "" {
					carvedFiles = append(carvedFiles, fileName)
				}
			}
		}
	}

	return carvedFiles, nil
}

// carveFile carves a file of the specified type from the given offset
func (c *FileCarver) carveFile(fileType string, offset int64) (string, error) {
	// Check for cancellation
	if c.isCancelled() {
		return "", fmt.Errorf("operation cancelled")
	}

	// Get file extension
	extension := c.extensions[fileType]

	// Generate a unique filename
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("%s_%s_0x%X%s", fileType, timestamp, offset, extension)
	filePath := filepath.Join(c.outputDir, fileName)

	// Create the output file
	outFile, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Determine file end marker based on file type
	var endMarker []byte

	switch fileType {
	case "JPEG":
		// JPEG ends with FF D9
		endMarker = []byte{0xFF, 0xD9}
	case "PNG":
		// PNG ends with IEND chunk
		endMarker = []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}
	case "PDF":
		// PDF ends with %%EOF
		endMarker = []byte{0x25, 0x25, 0x45, 0x4F, 0x46}
	default:
		// For other types, use a fixed size or try to detect end markers
	}

	// Read and write the file in chunks
	buffer := make([]byte, 64*1024) // 64KB chunks
	currentOffset := offset
	totalBytesWritten := int64(0)

	for {
		// Check for cancellation
		if c.isCancelled() {
			return "", fmt.Errorf("operation cancelled")
		}

		// Check if we've reached the maximum file size
		if c.maxFileSize > 0 && totalBytesWritten >= c.maxFileSize {
			break
		}

		// Read a chunk
		n, err := c.volume.readAt(buffer, currentOffset)
		if err != nil || n == 0 {
			break
		}

		// Look for end marker if defined
		endPos := -1
		if endMarker != nil {
			endPos = bytes.Index(buffer[:n], endMarker)
			if endPos >= 0 {
				// Include the end marker in the file
				endPos += len(endMarker)
			}
		}

		// Write the chunk (or part of it if end marker found)
		var bytesToWrite int
		if endPos >= 0 {
			bytesToWrite = endPos
		} else {
			bytesToWrite = n
		}

		_, err = outFile.Write(buffer[:bytesToWrite])
		if err != nil {
			return "", fmt.Errorf("failed to write to output file: %v", err)
		}

		totalBytesWritten += int64(bytesToWrite)
		currentOffset += int64(bytesToWrite)

		// If we found an end marker, we're done
		if endPos >= 0 {
			break
		}

		// If we've reached the end of the volume, we're done
		if n < len(buffer) {
			break
		}
	}

	// If we didn't write anything, delete the file and return empty
	if totalBytesWritten == 0 {
		outFile.Close()
		os.Remove(filePath)
		return "", nil
	}

	return filePath, nil
}

// validateFile performs format-specific validation of the carved file
func (c *FileCarver) validateFile(file *CarvedFile) bool {
	// Basic validation
	if file == nil || len(file.Data) == 0 {
		return false
	}

	// Format-specific validation
	switch file.Signature.Name {
	case "JPEG":
		return validateJPEG(file.Data)
	case "PNG":
		return validatePNG(file.Data)
	case "PDF":
		return validatePDF(file.Data)
	default:
		// Default to true for unknown formats
		return true
	}
}

// Format-specific validation functions
func validateJPEG(data []byte) bool {
	// Check for valid JPEG structure
	if len(data) < 4 {
		return false
	}

	// Verify SOI marker
	if !bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}) {
		return false
	}

	// Verify EOI marker
	if !bytes.HasSuffix(data, []byte{0xFF, 0xD9}) {
		return false
	}

	return true
}

func validatePNG(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Verify PNG signature
	signature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(data, signature) {
		return false
	}

	// Verify IEND chunk
	endChunk := []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}
	if !bytes.HasSuffix(data, endChunk) {
		return false
	}

	return true
}

func validatePDF(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Verify PDF header
	if !bytes.HasPrefix(data, []byte("%PDF")) {
		return false
	}

	// Verify EOF marker
	if !bytes.Contains(data[len(data)-1024:], []byte("%%EOF")) {
		return false
	}

	return true
}

// Options returns the carver options
func (c *FileCarver) Options() *CarveOptions {
	return &CarveOptions{
		OutputDir:   c.outputDir,
		FileTypes:   []string{},
		MaxFileSize: c.maxFileSize,
		MaxResults:  0,
		BufferSize:  c.bufferSize,
	}
}

// SetOptions sets the carver options
func (c *FileCarver) SetOptions(opts CarveOptions) {
	c.outputDir = opts.OutputDir
	c.maxFileSize = opts.MaxFileSize
	c.bufferSize = opts.BufferSize
}
