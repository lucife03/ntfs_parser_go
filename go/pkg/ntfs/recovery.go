package ntfs

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileRecoverer handles recovery of deleted files
type FileRecoverer struct {
	volume *NTFSVolume
}

// NewFileRecoverer creates a new file recoverer
func NewFileRecoverer(volume *NTFSVolume) *FileRecoverer {
	return &FileRecoverer{
		volume: volume,
	}
}

// RecoverFile attempts to recover a deleted file
func (r *FileRecoverer) RecoverFile(file *FileInfo, opts RecoveryOptions) error {
	if !file.IsDeleted() {
		return fmt.Errorf("file is not deleted")
	}

	// Validate file content if requested
	if opts.ValidateContent {
		if err := r.validateFileContent(file); err != nil {
			if !opts.RepairMode {
				return fmt.Errorf("file content validation failed: %v", err)
			}
			// Try to repair in repair mode
			if err := r.repairFileContent(file); err != nil {
				return fmt.Errorf("file repair failed: %v", err)
			}
		}
	}

	// Get file content
	data, err := r.volume.ReadFileContent(file)
	if err != nil {
		return fmt.Errorf("failed to read file content: %v", err)
	}

	// Create output path
	outputPath := r.buildOutputPath(file, opts)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Write recovered file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write recovered file: %v", err)
	}

	return nil
}

// RecoverDirectory attempts to recover a deleted directory and its contents
func (r *FileRecoverer) RecoverDirectory(dir *FileInfo, opts RecoveryOptions) error {
	if !dir.IsDirectory() {
		return fmt.Errorf("not a directory")
	}

	// Get all files in the directory
	scanner := NewScanner(r.volume)
	scanner.opts.IncludeDeleted = true

	files, err := scanner.ListFiles(true)
	if err != nil {
		return fmt.Errorf("failed to list directory contents: %v", err)
	}

	// Recover each file
	for _, file := range files {
		if err := r.RecoverFile(file, opts); err != nil {
			fmt.Printf("Warning: Failed to recover %s: %v\n", file.Name, err)
			continue
		}
	}

	return nil
}

// validateFileContent checks if file content appears valid
func (r *FileRecoverer) validateFileContent(file *FileInfo) error {
	// Check for valid data attribute
	var dataAttr *Attribute
	attrs := file.Attributes()
	for i := range attrs {
		if attrs[i].Type == ATTR_DATA && attrs[i].Name == "" {
			dataAttr = &attrs[i]
			break
		}
	}

	if dataAttr == nil {
		return fmt.Errorf("no valid data attribute found")
	}

	// For resident data, check if content size matches
	if dataAttr.Resident {
		if int64(len(dataAttr.Data)) != file.Size {
			return fmt.Errorf("resident data size mismatch")
		}
		return nil
	}

	// For non-resident data, validate data runs
	if dataAttr.NonResident == nil {
		return fmt.Errorf("invalid non-resident attribute")
	}

	// Parse and validate data runs
	runs, err := parseDataRuns(dataAttr.Data)
	if err != nil {
		return fmt.Errorf("invalid data runs: %v", err)
	}

	// Validate total size from runs
	var totalSize uint64
	for _, run := range runs {
		totalSize += run.ClusterCount * uint64(r.volume.clusterSize)
	}

	if totalSize < dataAttr.NonResident.RealSize {
		return fmt.Errorf("data runs size less than expected")
	}

	return nil
}

// repairFileContent attempts to repair corrupted file content
func (r *FileRecoverer) repairFileContent(file *FileInfo) error {
	// Find data attribute
	var dataAttr *Attribute
	attrs := file.Attributes()
	for i := range attrs {
		if attrs[i].Type == ATTR_DATA && attrs[i].Name == "" {
			dataAttr = &attrs[i]
			break
		}
	}

	if dataAttr == nil {
		return fmt.Errorf("no data attribute found")
	}

	if dataAttr.Resident {
		// For resident data, not much we can do to repair
		return fmt.Errorf("cannot repair resident data")
	}

	// For non-resident data, try to recover valid clusters
	runs, err := parseDataRuns(dataAttr.Data)
	if err != nil {
		return fmt.Errorf("failed to parse data runs: %v", err)
	}

	// Validate each run and mark bad clusters
	var validRuns []DataRun
	for _, run := range runs {
		if r.isValidClusterRun(run) {
			validRuns = append(validRuns, run)
		}
	}

	if len(validRuns) == 0 {
		return fmt.Errorf("no valid data runs found")
	}

	// Update data runs to only include valid ones
	dataAttr.Data = encodeDataRuns(validRuns)
	return nil
}

// isValidClusterRun checks if a cluster run appears valid
func (r *FileRecoverer) isValidClusterRun(run DataRun) bool {
	if run.IsHole {
		return true // Sparse runs are valid
	}

	// Check if clusters are within volume bounds
	totalClusters := uint64(r.volume.volumeSize) / uint64(r.volume.clusterSize)
	return run.StartCluster >= 0 && uint64(run.StartCluster)+run.ClusterCount <= totalClusters
}

// buildOutputPath creates the output path for a recovered file
func (r *FileRecoverer) buildOutputPath(file *FileInfo, opts RecoveryOptions) string {
	if opts.PreserveTree {
		// Preserve directory structure
		return filepath.Join(opts.OutputPath, file.Path)
	}

	// Flat structure with unique names
	baseName := filepath.Base(file.Name)
	ext := filepath.Ext(baseName)
	nameWithoutExt := baseName[:len(baseName)-len(ext)]

	// Add record number to ensure uniqueness
	return filepath.Join(opts.OutputPath,
		fmt.Sprintf("%s_rec%d%s", nameWithoutExt, file.RecordNumber, ext))
}

// encodeDataRuns encodes data runs back to bytes
func encodeDataRuns(runs []DataRun) []byte {
	// TODO: Implement data run encoding
	// This is needed for the repair functionality
	return nil
}
