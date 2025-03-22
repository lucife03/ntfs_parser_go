package ntfs

import (
	"encoding/binary"
	"fmt"
)

// Security ID constants
const (
	SECURITY_DESCRIPTOR_REVISION = 1
	SE_DACL_PRESENT              = 0x0004
	SE_SACL_PRESENT              = 0x0010
)

// Access mask constants
const (
	FILE_READ_DATA        = 0x0001
	FILE_WRITE_DATA       = 0x0002
	FILE_APPEND_DATA      = 0x0004
	FILE_READ_EA          = 0x0008
	FILE_WRITE_EA         = 0x0010
	FILE_EXECUTE          = 0x0020
	FILE_READ_ATTRIBUTES  = 0x0080
	FILE_WRITE_ATTRIBUTES = 0x0100
	DELETE                = 0x00010000
	READ_CONTROL          = 0x00020000
	WRITE_DAC             = 0x00040000
	WRITE_OWNER           = 0x00080000
	SYNCHRONIZE           = 0x00100000
	GENERIC_ALL           = 0x10000000
	GENERIC_EXECUTE       = 0x20000000
	GENERIC_WRITE         = 0x40000000
	GENERIC_READ          = 0x80000000
)

// SecurityDescriptor represents an NTFS security descriptor
type SecurityDescriptor struct {
	Revision uint8
	Flags    uint8
	OwnerSID *SID
	GroupSID *SID
	DACL     *ACL
	SACL     *ACL
}

// SID represents a security identifier
type SID struct {
	Revision     uint8
	SubAuthCount uint8
	Authority    [6]byte
	SubAuth      []uint32
}

// ACL represents an access control list
type ACL struct {
	Revision uint8
	ACEs     []ACE
}

// ACE represents an access control entry
type ACE struct {
	Type       uint8
	Flags      uint8
	AccessMask uint32
	SID        *SID
}

// SecurityParser handles security descriptor parsing
type SecurityParser struct {
	volume *NTFSVolume
}

// NewSecurityParser creates a new security parser instance
func NewSecurityParser(volume *NTFSVolume) *SecurityParser {
	return &SecurityParser{
		volume: volume,
	}
}

// ParseSecurityDescriptor parses a security descriptor from raw data
func (sp *SecurityParser) ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too small")
	}

	sd := &SecurityDescriptor{
		Revision: data[0],
		Flags:    data[1],
	}

	// Get offsets
	ownerOffset := binary.LittleEndian.Uint32(data[4:])
	groupOffset := binary.LittleEndian.Uint32(data[8:])
	saclOffset := binary.LittleEndian.Uint32(data[12:])
	daclOffset := binary.LittleEndian.Uint32(data[16:])

	// Parse owner SID
	if ownerOffset > 0 && ownerOffset < uint32(len(data)) {
		sid, err := sp.parseSID(data[ownerOffset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing owner SID: %v", err)
		}
		sd.OwnerSID = sid
	}

	// Parse group SID
	if groupOffset > 0 && groupOffset < uint32(len(data)) {
		sid, err := sp.parseSID(data[groupOffset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing group SID: %v", err)
		}
		sd.GroupSID = sid
	}

	// Parse SACL if present
	if sd.Flags&SE_SACL_PRESENT != 0 && saclOffset > 0 && saclOffset < uint32(len(data)) {
		acl, err := sp.parseACL(data[saclOffset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing SACL: %v", err)
		}
		sd.SACL = acl
	}

	// Parse DACL if present
	if sd.Flags&SE_DACL_PRESENT != 0 && daclOffset > 0 && daclOffset < uint32(len(data)) {
		acl, err := sp.parseACL(data[daclOffset:])
		if err != nil {
			return nil, fmt.Errorf("error parsing DACL: %v", err)
		}
		sd.DACL = acl
	}

	return sd, nil
}

// parseSID parses a security identifier
func (sp *SecurityParser) parseSID(data []byte) (*SID, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("SID data too small")
	}

	sid := &SID{
		Revision:     data[0],
		SubAuthCount: data[1],
	}

	copy(sid.Authority[:], data[2:8])

	// Parse sub-authorities
	if len(data) < 8+4*int(sid.SubAuthCount) {
		return nil, fmt.Errorf("insufficient data for sub-authorities")
	}

	sid.SubAuth = make([]uint32, sid.SubAuthCount)
	for i := uint8(0); i < sid.SubAuthCount; i++ {
		offset := 8 + 4*i
		sid.SubAuth[i] = binary.LittleEndian.Uint32(data[offset:])
	}

	return sid, nil
}

// parseACL parses an access control list
func (sp *SecurityParser) parseACL(data []byte) (*ACL, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ACL data too small")
	}

	acl := &ACL{
		Revision: data[0],
	}

	aceCount := binary.LittleEndian.Uint16(data[4:])
	offset := uint16(8)

	// Parse ACEs
	for i := uint16(0); i < aceCount; i++ {
		if offset+4 > uint16(len(data)) {
			break
		}

		aceType := data[offset]
		aceFlags := data[offset+1]
		aceSize := binary.LittleEndian.Uint16(data[offset+2:])

		if offset+aceSize > uint16(len(data)) {
			break
		}

		ace := ACE{
			Type:       aceType,
			Flags:      aceFlags,
			AccessMask: binary.LittleEndian.Uint32(data[offset+4:]),
		}

		// Parse SID in ACE
		sid, err := sp.parseSID(data[offset+8:])
		if err != nil {
			return nil, fmt.Errorf("error parsing ACE SID: %v", err)
		}
		ace.SID = sid

		acl.ACEs = append(acl.ACEs, ace)
		offset += aceSize
	}

	return acl, nil
}

// GetPermissionString returns a human-readable string of permissions
func (ace *ACE) GetPermissionString() string {
	var perms []string

	if ace.AccessMask&GENERIC_ALL != 0 {
		return "Full Control"
	}

	if ace.AccessMask&FILE_READ_DATA != 0 {
		perms = append(perms, "Read")
	}
	if ace.AccessMask&FILE_WRITE_DATA != 0 {
		perms = append(perms, "Write")
	}
	if ace.AccessMask&FILE_EXECUTE != 0 {
		perms = append(perms, "Execute")
	}
	if ace.AccessMask&DELETE != 0 {
		perms = append(perms, "Delete")
	}
	if ace.AccessMask&WRITE_DAC != 0 {
		perms = append(perms, "Change Permissions")
	}
	if ace.AccessMask&WRITE_OWNER != 0 {
		perms = append(perms, "Take Ownership")
	}

	if len(perms) == 0 {
		return "None"
	}

	return fmt.Sprintf("%v", perms)
}

// GetSIDString returns a string representation of the SID
func (sid *SID) GetSIDString() string {
	auth := binary.BigEndian.Uint64(append([]byte{0, 0}, sid.Authority[:]...))
	result := fmt.Sprintf("S-%d-%d", sid.Revision, auth)

	for _, sub := range sid.SubAuth {
		result += fmt.Sprintf("-%d", sub)
	}

	return result
}
