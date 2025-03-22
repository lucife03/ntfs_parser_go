package ntfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
)

// MetadataExtractor handles metadata extraction from NTFS files
type MetadataExtractor struct {
	volume *NTFSVolume
}

// NewMetadataExtractor creates a new metadata extractor
func NewMetadataExtractor(volume *NTFSVolume) *MetadataExtractor {
	return &MetadataExtractor{
		volume: volume,
	}
}

// ExtractMetadata extracts detailed metadata from a file
func (m *MetadataExtractor) ExtractMetadata(file *FileInfo) (*FileMetadata, error) {
	if file == nil {
		return nil, fmt.Errorf("nil file info")
	}

	metadata := &FileMetadata{
		Signatures:    make([]string, 0),
		ExtendedAttrs: make(map[string]string),
		Fragments:     make([]Fragment, 0),
	}

	// Get file content for analysis
	data, err := m.volume.ReadFileContent(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %v", err)
	}

	// Calculate file signatures
	hash := sha256.Sum256(data)
	metadata.Signatures = append(metadata.Signatures, "SHA256:"+hex.EncodeToString(hash[:]))

	// Detect MIME type based on signatures
	metadata.MIMEType = detectMIMEType(data)

	// Calculate entropy
	metadata.Entropy = calculateEntropy(data)

	// Get attributes list
	attrs := file.Attributes()

	// Check for compression
	for _, attr := range attrs {
		if attr.Type == ATTR_DATA && attr.Name == "" {
			metadata.IsCompressed = (attr.Flags & 0x0001) != 0
			break
		}
	}

	// Check for encryption
	metadata.IsEncrypted = isEncrypted(metadata.Entropy, data)

	// Get extended attributes
	for _, attr := range attrs {
		if attr.Type == ATTR_EA || attr.Type == ATTR_EA_INFORMATION {
			if attr.Resident {
				metadata.ExtendedAttrs[attr.Name] = string(attr.Data)
			}
		}
	}

	// Get file fragments
	for _, attr := range attrs {
		if attr.Type == ATTR_DATA && !attr.Resident && attr.NonResident != nil {
			runs, err := parseDataRuns(attr.Data)
			if err != nil {
				continue
			}
			for _, run := range runs {
				if !run.IsHole {
					metadata.Fragments = append(metadata.Fragments, Fragment{
						Offset: int64(run.StartCluster) * int64(m.volume.clusterSize),
						Size:   int64(run.ClusterCount) * int64(m.volume.clusterSize),
						Type:   "Data",
					})
				}
			}
		}
	}

	return metadata, nil
}

// detectMIMEType detects the MIME type based on file signatures
func detectMIMEType(data []byte) string {
	if len(data) < 8 {
		return "application/octet-stream"
	}

	// Common file signatures
	signatures := map[string][]byte{
		"image/jpeg":         {0xFF, 0xD8, 0xFF},
		"image/png":          {0x89, 0x50, 0x4E, 0x47},
		"image/gif":          {0x47, 0x49, 0x46, 0x38},
		"application/pdf":    {0x25, 0x50, 0x44, 0x46},
		"application/msword": {0xD0, 0xCF, 0x11, 0xE0},
	}

	for mimeType, sig := range signatures {
		if len(data) >= len(sig) && matchSignature(data, sig) {
			return mimeType
		}
	}

	return "application/octet-stream"
}

// calculateEntropy calculates Shannon entropy of the data
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Calculate byte frequency
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	size := float64(len(data))
	for _, count := range freq {
		p := float64(count) / size
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// isEncrypted attempts to detect if the file is encrypted
func isEncrypted(entropy float64, data []byte) bool {
	// High entropy is a good indicator of encryption
	if entropy > 7.9 {
		return true
	}

	// Check for common encryption headers
	if len(data) >= 4 {
		// Check for common encrypted file signatures
		encSignatures := [][]byte{
			{0x45, 0x4E, 0x43, 0x52}, // "ENCR"
			{0x44, 0x45, 0x53, 0x01}, // DES
		}

		for _, sig := range encSignatures {
			if matchSignature(data, sig) {
				return true
			}
		}
	}

	return false
}

// Helper function to match file signatures
func matchSignature(data, signature []byte) bool {
	if len(data) < len(signature) {
		return false
	}
	for i := range signature {
		if data[i] != signature[i] {
			return false
		}
	}
	return true
}
