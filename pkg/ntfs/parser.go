package ntfs

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	MFT_RECORD_SIGNATURE = "FILE"
	WINDOWS_TICK         = 10000000
	WINDOWS_TO_UNIX      = 11644473600
)

// MFT Record Flags
const (
	MFT_RECORD_IN_USE       = 0x0001
	MFT_RECORD_IS_DIRECTORY = 0x0002
)

// ParseMFTRecord parses a raw MFT record into a FileRecord structure
func ParseMFTRecord(data []byte) (*FileRecord, error) {
	if len(data) < 42 { // Minimum size for header
		return nil, fmt.Errorf("record too small")
	}

	record := &FileRecord{}

	// Parse header
	copy(record.Signature[:], data[0:4])
	if string(record.Signature[:]) != "FILE" {
		return nil, fmt.Errorf("invalid record signature")
	}

	record.UpdateSequenceOffset = binary.LittleEndian.Uint16(data[4:6])
	record.UpdateSequenceSize = binary.LittleEndian.Uint16(data[6:8])
	record.LogFileSequence = binary.LittleEndian.Uint64(data[8:16])
	record.SequenceNum = binary.LittleEndian.Uint16(data[16:18])
	record.HardLinkCount = binary.LittleEndian.Uint16(data[18:20])
	record.FirstAttributeOffset = binary.LittleEndian.Uint16(data[20:22])
	record.Flags = binary.LittleEndian.Uint16(data[22:24])
	record.RealSize = binary.LittleEndian.Uint32(data[24:28])
	record.AllocSize = binary.LittleEndian.Uint32(data[28:32])
	record.BaseRecord = binary.LittleEndian.Uint64(data[32:40])
	record.NextAttrID = binary.LittleEndian.Uint16(data[40:42])

	// Parse flags
	record.IsDirectory = (record.Flags & 0x0002) != 0
	record.IsDeleted = (record.Flags & 0x0001) != 0

	// Parse attributes
	offset := int(record.FirstAttributeOffset)
	for offset < len(data) {
		attr, newOffset, err := parseAttribute(data[offset:])
		if err != nil {
			break // Stop at first error
		}
		if attr.Type == 0xFFFFFFFF {
			break // End marker
		}
		record.Attributes = append(record.Attributes, *attr)
		offset += newOffset
	}

	return record, nil
}

// parseAttribute parses a single attribute from raw data
func parseAttribute(data []byte) (*Attribute, int, error) {
	if len(data) < 16 { // Minimum size for attribute header
		return nil, 0, fmt.Errorf("attribute too small")
	}

	attr := &Attribute{}
	attr.Type = binary.LittleEndian.Uint32(data[0:4])
	if attr.Type == 0xFFFFFFFF {
		return attr, 4, nil // End marker
	}

	length := binary.LittleEndian.Uint32(data[4:8])
	if int(length) > len(data) {
		return nil, 0, fmt.Errorf("attribute length exceeds data")
	}

	nonResident := data[8] != 0
	nameLength := data[9]
	nameOffset := binary.LittleEndian.Uint16(data[10:12])
	flags := binary.LittleEndian.Uint16(data[12:14])
	attrID := binary.LittleEndian.Uint16(data[14:16])

	attr.Length = length
	attr.Resident = !nonResident
	attr.NameLength = nameLength
	attr.NameOffset = nameOffset
	attr.Flags = flags
	attr.ID = attrID

	// Parse name if present
	if nameLength > 0 && int(nameOffset) < len(data) {
		nameEnd := int(nameOffset) + int(nameLength)*2 // UTF-16
		if nameEnd <= len(data) {
			attr.Name = decodeUTF16(data[nameOffset:nameEnd])
		}
	}

	if attr.Resident {
		contentLength := binary.LittleEndian.Uint32(data[16:20])
		contentOffset := binary.LittleEndian.Uint16(data[20:22])
		if int(contentOffset)+int(contentLength) <= len(data) {
			attr.Data = make([]byte, contentLength)
			copy(attr.Data, data[contentOffset:contentOffset+uint16(contentLength)])
		}
	} else {
		// Parse non-resident header
		if len(data) < 64 { // Minimum size for non-resident header
			return nil, 0, fmt.Errorf("non-resident attribute too small")
		}

		attr.NonResident = &NonResidentAttribute{
			StartVCN:        binary.LittleEndian.Uint64(data[16:24]),
			LastVCN:         binary.LittleEndian.Uint64(data[24:32]),
			DataRunOffset:   binary.LittleEndian.Uint16(data[32:34]),
			CompressionUnit: binary.LittleEndian.Uint16(data[34:36]),
			AllocatedSize:   binary.LittleEndian.Uint64(data[40:48]),
			RealSize:        binary.LittleEndian.Uint64(data[48:56]),
			StreamSize:      binary.LittleEndian.Uint64(data[56:64]),
		}

		// Get data runs
		if int(attr.NonResident.DataRunOffset) < len(data) {
			attr.Data = data[attr.NonResident.DataRunOffset:length]
		}
	}

	return attr, int(length), nil
}

// decodeUTF16 decodes UTF-16 bytes to string
func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}

	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	runes := make([]rune, len(u16s))
	for i, u16 := range u16s {
		runes[i] = rune(u16)
	}
	return string(runes)
}

// parseFileNameAttr parses a $FILE_NAME attribute
func parseFileNameAttr(data []byte) (string, *FileNameTimes, error) {
	if len(data) < 66 { // Minimum size for $FILE_NAME
		return "", nil, fmt.Errorf("$FILE_NAME attribute too small")
	}

	nameLength := data[64]
	if len(data) < 66+int(nameLength)*2 {
		return "", nil, fmt.Errorf("$FILE_NAME attribute truncated")
	}

	times := &FileNameTimes{
		Creation: decodeWindowsTime(binary.LittleEndian.Uint64(data[8:16])),
		Modified: decodeWindowsTime(binary.LittleEndian.Uint64(data[16:24])),
		MFTMod:   decodeWindowsTime(binary.LittleEndian.Uint64(data[24:32])),
		Access:   decodeWindowsTime(binary.LittleEndian.Uint64(data[32:40])),
	}

	name := decodeUTF16(data[66 : 66+nameLength*2])
	return name, times, nil
}

// FileNameTimes contains timestamps from $FILE_NAME attribute
type FileNameTimes struct {
	Creation time.Time
	Modified time.Time
	MFTMod   time.Time
	Access   time.Time
}

// decodeWindowsTime converts Windows timestamp to Go time.Time
func decodeWindowsTime(t uint64) time.Time {
	// Windows time is 100-nanosecond intervals since January 1, 1601 UTC
	const windowsToUnixEpoch = 116444736000000000
	return time.Unix(0, int64((t-windowsToUnixEpoch)*100))
}

// createFileInfo creates a FileInfo from parsed data
func createFileInfo(record *FileRecord, recordNumber uint64, volume *NTFSVolume) *FileInfo {
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
		if attr.Type == ATTR_FILE_NAME {
			name, times, err := parseFileNameAttr(attr.Data)
			if err == nil {
				info.Name = name
				info.CreationTime = times.Creation
				info.ModifiedTime = times.Modified
				info.MFTModifiedTime = times.MFTMod
				info.AccessTime = times.Access
				break
			}
		}
	}

	// Get file size from $DATA attribute
	for _, attr := range record.Attributes {
		if attr.Type == ATTR_DATA && attr.Name == "" {
			if attr.Resident {
				info.Size = int64(len(attr.Data))
			} else if attr.NonResident != nil {
				info.Size = int64(attr.NonResident.RealSize)
			}
			break
		}
	}

	return info
}

// windowsTimeToUnix converts Windows filetime to Unix timestamp
func windowsTimeToUnix(winTime uint64) time.Time {
	secs := int64(winTime/WINDOWS_TICK - WINDOWS_TO_UNIX)
	nsecs := int64((winTime % WINDOWS_TICK) * 100)
	return time.Unix(secs, nsecs)
}

// getFileInfo extracts file information from attributes
func (v *NTFSVolume) getFileInfo(record *FileRecord) *FileInfo {
	info := &FileInfo{
		RecordNumber: uint64(record.LogFileSequence),
		IsDir:        record.IsDirectory,
		Deleted:      record.IsDeleted,
		AttrList:     record.Attributes,
		volume:       v,
	}

	for _, attr := range record.Attributes {
		switch attr.Type {
		case ATTR_FILE_NAME:
			if len(attr.Data) >= 66 { // Minimum size for $FILE_NAME attribute
				info.Name = decodeUTF16(attr.Data[66 : 66+attr.Data[64]*2])
				info.CreationTime = windowsTimeToUnix(binary.LittleEndian.Uint64(attr.Data[8:16]))
				info.ModifiedTime = windowsTimeToUnix(binary.LittleEndian.Uint64(attr.Data[16:24]))
				info.MFTModifiedTime = windowsTimeToUnix(binary.LittleEndian.Uint64(attr.Data[24:32]))
				info.AccessTime = windowsTimeToUnix(binary.LittleEndian.Uint64(attr.Data[32:40]))
			}
		case ATTR_DATA:
			if !attr.Resident {
				if attr.NonResident != nil {
					info.Size = int64(attr.NonResident.RealSize)
				}
			} else {
				info.Size = int64(len(attr.Data))
			}
		}
	}

	return info
}
