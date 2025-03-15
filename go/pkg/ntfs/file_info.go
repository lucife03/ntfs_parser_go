package ntfs

import (
	"fmt"
)

// SecurityDescriptor returns the raw security descriptor data for the file
func (fi *FileInfo) SecurityDescriptor() ([]byte, error) {
	// Look for the security descriptor attribute
	for _, attr := range fi.AttrList {
		if attr.Type == ATTR_SECURITY_DESCRIPTOR {
			if attr.Resident {
				return attr.Data, nil
			}
			// Handle non-resident security descriptor
			data, err := fi.volume.readNonResidentAttribute(&attr)
			if err != nil {
				return nil, fmt.Errorf("error reading non-resident security descriptor: %v", err)
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("security descriptor not found")
}
