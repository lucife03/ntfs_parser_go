package ntfs

import (
	"fmt"
	"sort"
	"sync"
)

// TimelineGenerator handles timeline generation
type TimelineGenerator struct {
	volume  *NTFSVolume
	scanner *Scanner
	opts    *TimelineOptions
	// Add cancellation support
	cancelChan chan struct{}
	// Add progress callback
	progressCallback func(processed, total int64, status string)
}

// NewTimelineGenerator creates a new timeline generator
func NewTimelineGenerator(volume *NTFSVolume, opts *TimelineOptions) *TimelineGenerator {
	if opts == nil {
		opts = &TimelineOptions{
			IncludeDeleted: true,
			EventTypes:     []string{"creation", "modification", "access", "mft", "deletion"},
		}
	}

	return &TimelineGenerator{
		volume:     volume,
		scanner:    NewScanner(volume),
		opts:       opts,
		cancelChan: make(chan struct{}),
	}
}

// SetProgressCallback sets a callback function for progress reporting
func (t *TimelineGenerator) SetProgressCallback(callback func(processed, total int64, status string)) {
	t.progressCallback = callback
	// Also set it for the scanner
	t.scanner.SetProgressCallback(callback)
}

// Cancel cancels any ongoing timeline generation
func (t *TimelineGenerator) Cancel() {
	select {
	case t.cancelChan <- struct{}{}:
	default:
		// Channel already has a value, no need to send again
	}
	// Also cancel the scanner
	t.scanner.Cancel()
}

// reportProgress reports progress if a callback is set
func (t *TimelineGenerator) reportProgress(processed, total int64, status string) {
	if t.progressCallback != nil {
		t.progressCallback(processed, total, status)
	}
}

// isCancelled checks if the operation has been cancelled
func (t *TimelineGenerator) isCancelled() bool {
	select {
	case <-t.cancelChan:
		return true
	default:
		return false
	}
}

// GenerateTimeline generates a timeline of filesystem events
func (t *TimelineGenerator) GenerateTimeline() ([]TimelineEntry, error) {
	// Reset cancellation channel
	t.cancelChan = make(chan struct{})

	// Get all files including deleted if requested
	t.reportProgress(0, 100, "Listing files...")
	files, err := t.scanner.ListFiles(t.opts.IncludeDeleted)
	if err != nil {
		return nil, fmt.Errorf("error listing files: %v", err)
	}

	if t.isCancelled() {
		return nil, fmt.Errorf("operation cancelled")
	}

	t.reportProgress(30, 100, fmt.Sprintf("Processing %d files for timeline...", len(files)))

	// Process files in parallel for better performance
	var (
		entries    = make([]TimelineEntry, 0)
		entriesMux = &sync.Mutex{}
		wg         = &sync.WaitGroup{}
		errors     = make([]error, 0)
		processed  int64
		total      = int64(len(files))
	)

	// Create a channel for files to process
	filesChan := make(chan *FileInfo, 100)

	// Determine number of worker goroutines based on CPU count
	numWorkers := min(8, len(files))
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for file := range filesChan {
				// Check for cancellation
				if t.isCancelled() {
					return
				}

				// Process file for timeline events
				fileEntries := t.processFileForTimeline(file)

				// Add entries to the result
				if len(fileEntries) > 0 {
					entriesMux.Lock()
					entries = append(entries, fileEntries...)
					entriesMux.Unlock()
				}

				// Update progress
				entriesMux.Lock()
				processed++
				progress := processed*70/total + 30 // 30-100% range
				t.reportProgress(progress, 100, fmt.Sprintf("Processed %d of %d files...", processed, total))
				entriesMux.Unlock()
			}
		}()
	}

	// Send files to workers
	go func() {
		for _, file := range files {
			// Check for cancellation
			if t.isCancelled() {
				close(filesChan)
				return
			}

			filesChan <- file
		}
		close(filesChan)
	}()

	// Wait for all workers to finish
	wg.Wait()

	if t.isCancelled() {
		return nil, fmt.Errorf("operation cancelled")
	}

	// Report any errors
	if len(errors) > 0 {
		fmt.Printf("Encountered %d errors during timeline generation. First few errors:\n", len(errors))
		for i := 0; i < min(3, len(errors)); i++ {
			fmt.Printf("- %v\n", errors[i])
		}
		if len(errors) > 3 {
			fmt.Printf("- ... and %d more errors\n", len(errors)-3)
		}
	}

	// Sort entries by timestamp
	t.reportProgress(95, 100, "Sorting timeline entries...")
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	t.reportProgress(100, 100, fmt.Sprintf("Timeline generation complete. Found %d events.", len(entries)))

	return entries, nil
}

// processFileForTimeline processes a single file for timeline events
func (t *TimelineGenerator) processFileForTimeline(file *FileInfo) []TimelineEntry {
	var entries []TimelineEntry

	// Skip if outside time range
	if !t.opts.StartTime.IsZero() && file.CreationTime.Before(t.opts.StartTime) &&
		!t.opts.EndTime.IsZero() && file.ModifiedTime.After(t.opts.EndTime) &&
		!t.opts.EndTime.IsZero() && file.AccessTime.After(t.opts.EndTime) &&
		!t.opts.EndTime.IsZero() && file.MFTModifiedTime.After(t.opts.EndTime) {
		return entries
	}

	// Add events based on requested types
	for _, eventType := range t.opts.EventTypes {
		switch eventType {
		case "creation":
			if t.opts.StartTime.IsZero() || !file.CreationTime.Before(t.opts.StartTime) {
				if t.opts.EndTime.IsZero() || !file.CreationTime.After(t.opts.EndTime) {
					entries = append(entries, TimelineEntry{
						Timestamp: file.CreationTime,
						EventType: "Creation",
						File:      file,
						Details:   "File created",
					})
				}
			}
		case "modification":
			if t.opts.StartTime.IsZero() || !file.ModifiedTime.Before(t.opts.StartTime) {
				if t.opts.EndTime.IsZero() || !file.ModifiedTime.After(t.opts.EndTime) {
					entries = append(entries, TimelineEntry{
						Timestamp: file.ModifiedTime,
						EventType: "Modified",
						File:      file,
						Details:   "Content modified",
					})
				}
			}
		case "access":
			if t.opts.StartTime.IsZero() || !file.AccessTime.Before(t.opts.StartTime) {
				if t.opts.EndTime.IsZero() || !file.AccessTime.After(t.opts.EndTime) {
					entries = append(entries, TimelineEntry{
						Timestamp: file.AccessTime,
						EventType: "Access",
						File:      file,
						Details:   "File accessed",
					})
				}
			}
		case "mft":
			if t.opts.StartTime.IsZero() || !file.MFTModifiedTime.Before(t.opts.StartTime) {
				if t.opts.EndTime.IsZero() || !file.MFTModifiedTime.After(t.opts.EndTime) {
					entries = append(entries, TimelineEntry{
						Timestamp: file.MFTModifiedTime,
						EventType: "MFT Update",
						File:      file,
						Details:   "MFT entry modified",
					})
				}
			}
		case "deletion":
			if file.IsDeleted() {
				// Use modified time as deletion time (best approximation)
				if t.opts.StartTime.IsZero() || !file.ModifiedTime.Before(t.opts.StartTime) {
					if t.opts.EndTime.IsZero() || !file.ModifiedTime.After(t.opts.EndTime) {
						entries = append(entries, TimelineEntry{
							Timestamp: file.ModifiedTime,
							EventType: "Deletion",
							File:      file,
							Details:   "File deleted",
						})
					}
				}
			}
		}
	}

	return entries
}

// ExportTimeline exports the timeline to various formats
func (t *TimelineGenerator) ExportTimeline(entries []TimelineEntry, format string, outputPath string) error {
	switch format {
	case "csv":
		return t.exportTimelineCSV(entries, outputPath)
	case "json":
		return t.exportTimelineJSON(entries, outputPath)
	case "txt":
		return t.exportTimelineTXT(entries, outputPath)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportTimelineCSV exports the timeline to CSV format
func (t *TimelineGenerator) exportTimelineCSV(entries []TimelineEntry, outputPath string) error {
	// Implementation would go here
	return fmt.Errorf("CSV export not implemented yet")
}

// exportTimelineJSON exports the timeline to JSON format
func (t *TimelineGenerator) exportTimelineJSON(entries []TimelineEntry, outputPath string) error {
	// Implementation would go here
	return fmt.Errorf("JSON export not implemented yet")
}

// exportTimelineTXT exports the timeline to text format
func (t *TimelineGenerator) exportTimelineTXT(entries []TimelineEntry, outputPath string) error {
	// Implementation would go here
	return fmt.Errorf("Text export not implemented yet")
}
