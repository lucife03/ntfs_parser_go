package ntfs

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// USN Journal related constants
const (
	USN_REASON_DATA_OVERWRITE        = 0x00000001
	USN_REASON_DATA_EXTEND           = 0x00000002
	USN_REASON_DATA_TRUNCATION       = 0x00000004
	USN_REASON_NAMED_DATA_OVERWRITE  = 0x00000010
	USN_REASON_NAMED_DATA_EXTEND     = 0x00000020
	USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
	USN_REASON_FILE_CREATE           = 0x00000100
	USN_REASON_FILE_DELETE           = 0x00000200
	USN_REASON_EA_CHANGE             = 0x00000400
	USN_REASON_SECURITY_CHANGE       = 0x00000800
	USN_REASON_RENAME_OLD_NAME       = 0x00001000
	USN_REASON_RENAME_NEW_NAME       = 0x00002000
	USN_REASON_INDEXABLE_CHANGE      = 0x00004000
	USN_REASON_BASIC_INFO_CHANGE     = 0x00008000
	USN_REASON_HARD_LINK_CHANGE      = 0x00010000
	USN_REASON_COMPRESSION_CHANGE    = 0x00020000
	USN_REASON_ENCRYPTION_CHANGE     = 0x00040000
	USN_REASON_OBJECT_ID_CHANGE      = 0x00080000
	USN_REASON_REPARSE_POINT_CHANGE  = 0x00100000
	USN_REASON_STREAM_CHANGE         = 0x00200000
	USN_REASON_CLOSE                 = 0x80000000
)

// JournalEntry represents a single USN journal entry
type JournalEntry struct {
	RecordLength     uint32
	MajorVersion     uint16
	MinorVersion     uint16
	FileReferenceNum uint64
	ParentRefNum     uint64
	USN              int64
	Timestamp        time.Time
	Reason           uint32
	SourceInfo       uint32
	SecurityID       uint32
	FileAttributes   uint32
	FileNameLength   uint16
	FileNameOffset   uint16
	FileName         string
}

// JournalParser handles USN journal parsing
type JournalParser struct {
	volume  *NTFSVolume
	options JournalOptions
}

// JournalOptions defines options for journal parsing
type JournalOptions struct {
	StartUSN        int64
	ReasonMask      uint32
	ReturnOnlyFiles bool
	MaxEntries      int
}

// NewJournalParser creates a new journal parser instance
func NewJournalParser(volume *NTFSVolume) *JournalParser {
	return &JournalParser{
		volume: volume,
		options: JournalOptions{
			StartUSN:        0,
			ReasonMask:      0xFFFFFFFF,
			ReturnOnlyFiles: false,
			MaxEntries:      1000,
		},
	}
}

// ParseJournal reads and parses the USN journal
func (jp *JournalParser) ParseJournal() ([]JournalEntry, error) {
	// Find $Extend\$UsnJrnl
	scanner := NewScanner(jp.volume)
	files, err := scanner.ListFiles(false)
	if err != nil {
		return nil, fmt.Errorf("error listing files: %v", err)
	}

	var journalFile *FileInfo
	for _, file := range files {
		if file.Name == "$UsnJrnl" && file.Path == "$Extend\\$UsnJrnl" {
			journalFile = file
			break
		}
	}

	if journalFile == nil {
		return nil, fmt.Errorf("USN journal not found")
	}

	// Find the $J data stream
	var journalData []byte
	for _, attr := range journalFile.Attributes() {
		if attr.Type == ATTR_DATA && attr.Name == "$J" {
			if attr.Resident {
				journalData = attr.Data
			} else {
				// Read non-resident journal data
				data, err := jp.volume.readNonResidentAttribute(&attr)
				if err != nil {
					return nil, fmt.Errorf("error reading journal data: %v", err)
				}
				journalData = data
			}
			break
		}
	}

	if journalData == nil {
		return nil, fmt.Errorf("journal data stream not found")
	}

	// Parse journal entries
	var entries []JournalEntry
	offset := 0
	for offset < len(journalData) {
		if offset+4 > len(journalData) {
			break
		}

		recordLength := binary.LittleEndian.Uint32(journalData[offset:])
		if recordLength == 0 {
			break
		}

		if offset+int(recordLength) > len(journalData) {
			break
		}

		entry, err := jp.parseJournalRecord(journalData[offset : offset+int(recordLength)])
		if err != nil {
			fmt.Printf("Warning: error parsing journal record at offset %d: %v\n", offset, err)
			offset += int(recordLength)
			continue
		}

		// Apply filters
		if entry.USN >= jp.options.StartUSN &&
			(entry.Reason&jp.options.ReasonMask != 0) &&
			(!jp.options.ReturnOnlyFiles || (entry.FileAttributes&FILE_ATTRIBUTE_DIRECTORY == 0)) {
			entries = append(entries, *entry)
		}

		if jp.options.MaxEntries > 0 && len(entries) >= jp.options.MaxEntries {
			break
		}

		offset += int(recordLength)
	}

	return entries, nil
}

// parseJournalRecord parses a single USN journal record
func (jp *JournalParser) parseJournalRecord(data []byte) (*JournalEntry, error) {
	if len(data) < 60 { // Minimum size for a USN record
		return nil, fmt.Errorf("record too small")
	}

	entry := &JournalEntry{
		RecordLength:     binary.LittleEndian.Uint32(data[0:]),
		MajorVersion:     binary.LittleEndian.Uint16(data[4:]),
		MinorVersion:     binary.LittleEndian.Uint16(data[6:]),
		FileReferenceNum: binary.LittleEndian.Uint64(data[8:]),
		ParentRefNum:     binary.LittleEndian.Uint64(data[16:]),
		USN:              int64(binary.LittleEndian.Uint64(data[24:])),
		Timestamp:        decodeWindowsTime(binary.LittleEndian.Uint64(data[32:])),
		Reason:           binary.LittleEndian.Uint32(data[40:]),
		SourceInfo:       binary.LittleEndian.Uint32(data[44:]),
		SecurityID:       binary.LittleEndian.Uint32(data[48:]),
		FileAttributes:   binary.LittleEndian.Uint32(data[52:]),
		FileNameLength:   binary.LittleEndian.Uint16(data[56:]),
		FileNameOffset:   binary.LittleEndian.Uint16(data[58:]),
	}

	// Extract filename
	if int(entry.FileNameOffset)+int(entry.FileNameLength) > len(data) {
		return nil, fmt.Errorf("invalid filename length or offset")
	}

	nameBytes := data[entry.FileNameOffset : entry.FileNameOffset+entry.FileNameLength]
	entry.FileName = decodeUTF16(nameBytes)

	return entry, nil
}

// GetReasonString returns a human-readable description of the USN reason
func (e *JournalEntry) GetReasonString() string {
	var reasons []string

	if e.Reason&USN_REASON_DATA_OVERWRITE != 0 {
		reasons = append(reasons, "Data Overwrite")
	}
	if e.Reason&USN_REASON_DATA_EXTEND != 0 {
		reasons = append(reasons, "Data Extend")
	}
	if e.Reason&USN_REASON_DATA_TRUNCATION != 0 {
		reasons = append(reasons, "Data Truncation")
	}
	if e.Reason&USN_REASON_FILE_CREATE != 0 {
		reasons = append(reasons, "File Create")
	}
	if e.Reason&USN_REASON_FILE_DELETE != 0 {
		reasons = append(reasons, "File Delete")
	}
	if e.Reason&USN_REASON_EA_CHANGE != 0 {
		reasons = append(reasons, "EA Change")
	}
	if e.Reason&USN_REASON_SECURITY_CHANGE != 0 {
		reasons = append(reasons, "Security Change")
	}
	if e.Reason&USN_REASON_RENAME_OLD_NAME != 0 {
		reasons = append(reasons, "Rename Old")
	}
	if e.Reason&USN_REASON_RENAME_NEW_NAME != 0 {
		reasons = append(reasons, "Rename New")
	}
	if e.Reason&USN_REASON_INDEXABLE_CHANGE != 0 {
		reasons = append(reasons, "Indexable Change")
	}
	if e.Reason&USN_REASON_BASIC_INFO_CHANGE != 0 {
		reasons = append(reasons, "Basic Info Change")
	}
	if e.Reason&USN_REASON_HARD_LINK_CHANGE != 0 {
		reasons = append(reasons, "Hard Link Change")
	}
	if e.Reason&USN_REASON_COMPRESSION_CHANGE != 0 {
		reasons = append(reasons, "Compression Change")
	}
	if e.Reason&USN_REASON_ENCRYPTION_CHANGE != 0 {
		reasons = append(reasons, "Encryption Change")
	}
	if e.Reason&USN_REASON_OBJECT_ID_CHANGE != 0 {
		reasons = append(reasons, "Object ID Change")
	}
	if e.Reason&USN_REASON_REPARSE_POINT_CHANGE != 0 {
		reasons = append(reasons, "Reparse Point Change")
	}
	if e.Reason&USN_REASON_STREAM_CHANGE != 0 {
		reasons = append(reasons, "Stream Change")
	}
	if e.Reason&USN_REASON_CLOSE != 0 {
		reasons = append(reasons, "Close")
	}

	return fmt.Sprintf("[%s]", strings.Join(reasons, ", "))
}

// Options returns the journal parser options
func (jp *JournalParser) Options() *JournalOptions {
	return &jp.options
}

// SetOptions sets the journal parser options
func (jp *JournalParser) SetOptions(opts JournalOptions) {
	jp.options = opts
}
