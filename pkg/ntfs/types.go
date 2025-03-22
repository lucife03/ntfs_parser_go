package ntfs

import (
	"fmt"
	"time"
)

// FileRecord represents an NTFS file record
type FileRecord struct {
	Signature            [4]byte
	UpdateSequenceOffset uint16
	UpdateSequenceSize   uint16
	LogFileSequence      uint64
	SequenceNum          uint16
	HardLinkCount        uint16
	FirstAttributeOffset uint16
	Flags                uint16
	RealSize             uint32
	AllocSize            uint32
	BaseRecord           uint64
	NextAttrID           uint16
	Attributes           []Attribute
	IsDirectory          bool
	IsDeleted            bool
}

// NonResidentAttribute contains information about non-resident attribute data
type NonResidentAttribute struct {
	StartVCN        uint64
	LastVCN         uint64
	DataRunOffset   uint16
	CompressionUnit uint16
	AllocatedSize   uint64
	RealSize        uint64
	StreamSize      uint64
}

// Attribute represents an NTFS attribute
type Attribute struct {
	Type        uint32
	Length      uint32
	Resident    bool
	NameLength  uint8
	NameOffset  uint16
	Flags       uint16
	ID          uint16
	Data        []byte
	Name        string
	NonResident *NonResidentAttribute
}

// FileInfo represents file information from an MFT record
type FileInfo struct {
	RecordNumber    uint64
	Name            string
	Path            string // Full path of the file
	Size            int64
	AllocatedSize   int64 // Physical size allocated on disk
	IsDir           bool
	Deleted         bool
	CreationTime    time.Time
	ModifiedTime    time.Time
	MFTModifiedTime time.Time
	AccessTime      time.Time
	AttrList        []Attribute // Changed from attrList to AttrList for public access
	volume          *NTFSVolume // Reference to the volume for operations
}

// VolumeReader provides access to an NTFS volume
type VolumeReader interface {
	// Open opens an NTFS volume at the given path
	Open(path string) error

	// Close closes the volume and releases resources
	Close() error

	// GetFileByPath returns a file by its path
	GetFileByPath(path string) (File, error)

	// GetFileByMFTIndex returns a file by its MFT index
	GetFileByMFTIndex(index uint64) (File, error)
}

// File represents an NTFS file or directory
type File interface {
	// Basic file information
	GetName() string
	GetPath() string
	GetSize() int64
	IsDirectory() bool
	IsDeleted() bool
	GetCreationTime() time.Time
	GetModifiedTime() time.Time
	GetAccessTime() time.Time
	GetMFTModifiedTime() time.Time

	// File operations
	Read(p []byte) (n int, err error)
	ReadAt(p []byte, off int64) (n int, err error)
	Attributes() []Attribute
	Streams() []Stream
}

// Stream represents an NTFS alternate data stream
type Stream interface {
	Name() string
	Size() int64
	Read(p []byte) (n int, err error)
	ReadAt(p []byte, off int64) (n int, err error)
}

// Metadata provides metadata extraction and timeline generation
type Metadata interface {
	// Extract metadata from a file
	ExtractMetadata(file File) (*FileMetadata, error)

	// Generate timeline of file system events
	GenerateTimeline(opts TimelineOptions) ([]TimelineEntry, error)
}

// ListOptions configures file listing behavior
type ListOptions struct {
	Pattern        string    // File name pattern (supports wildcards)
	IncludeDeleted bool      // Include deleted files
	IncludeSystem  bool      // Include system files
	MaxResults     int       // Maximum number of results (0 = unlimited)
	Recursive      bool      // Search recursively in directories
	MinSize        int64     // Minimum file size
	MaxSize        int64     // Maximum file size
	ModifiedAfter  time.Time // Modified after this time
	ModifiedBefore time.Time // Modified before this time
}

// SearchOptions configures file search behavior
type SearchOptions struct {
	NamePattern    string    // File name pattern
	ContentPattern string    // Content pattern to search for
	MinSize        int64     // Minimum file size
	MaxSize        int64     // Maximum file size
	ModifiedAfter  time.Time // Modified after this time
	ModifiedBefore time.Time // Modified before this time
	FileTypes      []string  // File types to include
	IncludeDeleted bool      // Include deleted files
	MaxResults     int       // Maximum number of results
}

// RecoveryOptions configures file recovery behavior
type RecoveryOptions struct {
	ValidateContent bool   // Attempt to validate file content
	RepairMode      bool   // Attempt to repair corrupted entries
	OutputPath      string // Path to save recovered files
	PreserveTree    bool   // Preserve directory structure
}

// TimelineOptions configures timeline generation
type TimelineOptions struct {
	StartTime      time.Time     // Start of timeline
	EndTime        time.Time     // End of timeline
	IncludeDeleted bool          // Include deleted files
	EventTypes     []string      // Types of events to include
	Resolution     time.Duration // Time resolution
}

// FileMetadata contains extended file metadata
type FileMetadata struct {
	Signatures    []string          // File signatures/magic numbers
	MIMEType      string            // MIME type
	Entropy       float64           // File entropy
	IsCompressed  bool              // Is file compressed
	IsEncrypted   bool              // Is file encrypted
	ExtendedAttrs map[string]string // Extended attributes
	Fragments     []Fragment        // File fragments information
}

// Fragment represents a file fragment on disk
type Fragment struct {
	Offset int64  // Offset in volume
	Size   int64  // Size in bytes
	Type   string // Fragment type
}

// TimelineEntry represents an event in the file system timeline
type TimelineEntry struct {
	Timestamp time.Time // When the event occurred
	EventType string    // Type of event
	File      File      // Associated file
	Details   string    // Additional event details
}

// ErrorCode represents specific error conditions
type ErrorCode int

const (
	ErrInvalidVolume ErrorCode = iota
	ErrFileNotFound
	ErrPermissionDenied
	ErrCorruptedRecord
	ErrUnsupportedFeature
)

// Error represents an error in the NTFS parser
type Error struct {
	Code    ErrorCode // Error code
	Message string    // Error message
	Op      string    // Operation that failed
	Path    string    // Path where error occurred
	Err     error     // Underlying error
}

// Make FileInfo implement File interface
func (f *FileInfo) GetName() string               { return f.Name }
func (f *FileInfo) GetPath() string               { return f.Path }
func (f *FileInfo) GetSize() int64                { return f.Size }
func (f *FileInfo) IsDirectory() bool             { return f.IsDir }
func (f *FileInfo) IsDeleted() bool               { return f.Deleted }
func (f *FileInfo) GetCreationTime() time.Time    { return f.CreationTime }
func (f *FileInfo) GetModifiedTime() time.Time    { return f.ModifiedTime }
func (f *FileInfo) GetAccessTime() time.Time      { return f.AccessTime }
func (f *FileInfo) GetMFTModifiedTime() time.Time { return f.MFTModifiedTime }
func (f *FileInfo) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("not implemented")
}
func (f *FileInfo) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, fmt.Errorf("not implemented")
}
func (f *FileInfo) Attributes() []Attribute { return f.AttrList }
func (f *FileInfo) Streams() []Stream       { return nil }
