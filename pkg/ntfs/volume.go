package ntfs

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// Partition entry structure
type PartitionEntry struct {
	Status        byte
	StartCHS      [3]byte
	PartitionType byte
	EndCHS        [3]byte
	StartLBA      uint32
	SectorCount   uint32
}

// NTFSVolume represents an NTFS volume
type NTFSVolume struct {
	device          []*os.File
	sectorSize      uint16
	clusterSize     uint64
	mftStart        uint64
	mftRecordSize   uint32
	volumeSize      int64
	bootSector      *BootSector
	partitionOffset int64
}

// BootSector represents the NTFS boot sector
type BootSector struct {
	JumpInstruction       [3]byte
	OemID                 [8]byte
	BytesPerSector        uint16
	SectorsPerCluster     uint8
	ReservedSectors       uint16
	MediaDescriptor       uint8
	SectorsPerTrack       uint16
	NumberOfHeads         uint16
	HiddenSectors         uint32
	TotalSectors          uint64
	MftStartLcn           uint64
	Mft2StartLcn          uint64
	ClustersPerMftRecord  int8
	ClustersPerIndexBlock int8
}

// NewNTFSVolume creates a new NTFS volume instance
func NewNTFSVolume(devicePath string) (*NTFSVolume, error) {
	// Try to open all split files
	var files []*os.File
	var totalSize int64

	// Get the base path and extension
	dir := filepath.Dir(devicePath)
	base := filepath.Base(devicePath)
	ext := filepath.Ext(base)
	nameWithoutExt := base[:len(base)-len(ext)]

	// If it's a split file (ends with .001), try to open all parts
	if ext == ".001" {
		for i := 1; ; i++ {
			path := filepath.Join(dir, fmt.Sprintf("%s.%03d", nameWithoutExt, i))
			file, err := os.OpenFile(path, os.O_RDONLY, 0)
			if err != nil {
				// If we can't open the next file, assume we've found all parts
				break
			}
			info, err := file.Stat()
			if err != nil {
				file.Close()
				return nil, fmt.Errorf("failed to get file size for part %d: %v", i, err)
			}
			totalSize += info.Size()
			files = append(files, file)
		}
	} else {
		// Single file
		file, err := os.OpenFile(devicePath, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to open device: %v", err)
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to get device size: %v", err)
		}
		totalSize = info.Size()
		files = append(files, file)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no valid NTFS files found")
	}

	volume := &NTFSVolume{
		device:     files,
		volumeSize: totalSize,
	}

	// First, try to find the NTFS partition
	offset, err := volume.findNTFSPartition()
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		return nil, fmt.Errorf("failed to find NTFS partition: %v", err)
	}
	volume.partitionOffset = offset

	fmt.Printf("Debug: Found NTFS partition at offset: %d (0x%X)\n", offset, offset)

	bootSector, err := volume.readBootSector()
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		return nil, err
	}

	volume.bootSector = bootSector
	volume.sectorSize = bootSector.BytesPerSector
	volume.clusterSize = uint64(bootSector.SectorsPerCluster) * uint64(bootSector.BytesPerSector)
	volume.mftStart = bootSector.MftStartLcn * volume.clusterSize

	// Calculate MFT record size
	if bootSector.ClustersPerMftRecord > 0 {
		volume.mftRecordSize = uint32(bootSector.ClustersPerMftRecord) * uint32(volume.clusterSize)
	} else {
		// If negative, it's the power of 2
		volume.mftRecordSize = 1 << uint32(-bootSector.ClustersPerMftRecord)
	}

	fmt.Printf("Volume Info:\n")
	fmt.Printf("- Number of parts: %d\n", len(files))
	fmt.Printf("- Total Volume Size: %d bytes\n", volume.volumeSize)
	fmt.Printf("- Sector Size: %d bytes\n", volume.sectorSize)
	fmt.Printf("- Cluster Size: %d bytes\n", volume.clusterSize)
	fmt.Printf("- MFT Start LCN: %d\n", bootSector.MftStartLcn)
	fmt.Printf("- MFT Start Offset: %d bytes\n", volume.mftStart)
	fmt.Printf("- MFT Record Size: %d bytes\n", volume.mftRecordSize)

	return volume, nil
}

// findNTFSPartition looks for an NTFS partition in the MBR
func (v *NTFSVolume) findNTFSPartition() (int64, error) {
	// Read MBR
	mbr := make([]byte, 512)
	n, err := v.readAt(mbr, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to read MBR: %v", err)
	}
	if n != 512 {
		return 0, fmt.Errorf("incomplete MBR read")
	}

	// Verify MBR signature
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return 0, fmt.Errorf("invalid MBR signature")
	}

	// Print first 16 bytes of MBR for debugging
	fmt.Printf("Debug: MBR first 16 bytes: % X\n", mbr[:16])

	// Parse partition table (starts at offset 0x1BE)
	for i := 0; i < 4; i++ {
		entry := mbr[0x1BE+i*16 : 0x1BE+(i+1)*16]
		partType := entry[4]
		startLBA := binary.LittleEndian.Uint32(entry[8:12])
		sectors := binary.LittleEndian.Uint32(entry[12:16])

		fmt.Printf("Debug: Partition %d - Type: %02X, Start: %d, Sectors: %d\n",
			i+1, partType, startLBA, sectors)

		// Check for NTFS partition types (0x07, 0x27)
		if partType == 0x07 || partType == 0x27 {
			offset := int64(startLBA) * 512 // Assuming 512-byte sectors

			// Verify NTFS signature at partition start
			boot := make([]byte, 512)
			n, err := v.readAt(boot, offset)
			if err != nil || n != 512 {
				continue
			}

			if string(boot[3:7]) == "NTFS" {
				return offset, nil
			}
		}
	}

	// If we didn't find an NTFS partition in the MBR, try the start of the file
	// Some raw images might not have an MBR
	boot := make([]byte, 512)
	n, err = v.readAt(boot, 0)
	if err == nil && n == 512 && string(boot[3:7]) == "NTFS" {
		return 0, nil
	}

	return 0, fmt.Errorf("no valid NTFS partition found")
}

// readAt reads from the split files at the specified offset
func (v *NTFSVolume) readAt(data []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative offset not allowed")
	}

	if offset >= v.volumeSize {
		return 0, fmt.Errorf("offset beyond volume size")
	}

	// Find which file contains the offset
	var currentOffset int64
	for i, file := range v.device {
		info, err := file.Stat()
		if err != nil {
			return 0, fmt.Errorf("failed to get file size for part %d: %v", i+1, err)
		}
		fileSize := info.Size()

		if offset < currentOffset+fileSize {
			// This file contains our data
			fileOffset := offset - currentOffset
			return file.ReadAt(data, fileOffset)
		}
		currentOffset += fileSize
	}

	return 0, fmt.Errorf("failed to find file containing offset %d", offset)
}

// readBootSector reads and parses the NTFS boot sector
func (v *NTFSVolume) readBootSector() (*BootSector, error) {
	bootSector := &BootSector{}
	data := make([]byte, 512)

	n, err := v.readAt(data, v.partitionOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read boot sector: %v", err)
	}

	if n != 512 {
		return nil, fmt.Errorf("incomplete boot sector read: got %d bytes", n)
	}

	// Print first 16 bytes for debugging
	fmt.Printf("Debug: Boot sector first 16 bytes: % X\n", data[:16])

	// Verify NTFS signature
	if string(data[3:7]) != "NTFS" {
		return nil, fmt.Errorf("NTFS signature not found")
	}

	// Parse boot sector fields
	copy(bootSector.JumpInstruction[:], data[0:3])
	copy(bootSector.OemID[:], data[3:11])

	bootSector.BytesPerSector = binary.LittleEndian.Uint16(data[0x0B:0x0D])
	bootSector.SectorsPerCluster = data[0x0D]
	bootSector.ReservedSectors = binary.LittleEndian.Uint16(data[0x0E:0x10])
	bootSector.MediaDescriptor = data[0x15]
	bootSector.SectorsPerTrack = binary.LittleEndian.Uint16(data[0x18:0x1A])
	bootSector.NumberOfHeads = binary.LittleEndian.Uint16(data[0x1A:0x1C])
	bootSector.HiddenSectors = binary.LittleEndian.Uint32(data[0x1C:0x20])
	bootSector.TotalSectors = binary.LittleEndian.Uint64(data[0x28:0x30])
	bootSector.MftStartLcn = binary.LittleEndian.Uint64(data[0x30:0x38])
	bootSector.Mft2StartLcn = binary.LittleEndian.Uint64(data[0x38:0x40])
	bootSector.ClustersPerMftRecord = int8(data[0x40])
	bootSector.ClustersPerIndexBlock = int8(data[0x44])

	// Print debug info
	fmt.Printf("Debug: Boot Sector Info:\n")
	fmt.Printf("- OEM ID: %s\n", string(data[3:11]))
	fmt.Printf("- Bytes per Sector: %d\n", bootSector.BytesPerSector)
	fmt.Printf("- Sectors per Cluster: %d\n", bootSector.SectorsPerCluster)
	fmt.Printf("- MFT Start LCN: %d\n", bootSector.MftStartLcn)
	fmt.Printf("- Clusters per MFT Record: %d\n", bootSector.ClustersPerMftRecord)

	return bootSector, nil
}

// Close closes all volume files
func (v *NTFSVolume) Close() error {
	var lastErr error
	for _, f := range v.device {
		if err := f.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// GetMFTRecord reads an MFT record at the specified index
func (v *NTFSVolume) GetMFTRecord(index uint64) ([]byte, error) {
	// Calculate absolute offset
	mftOffset := v.partitionOffset + int64(v.mftStart) + int64(index*uint64(v.mftRecordSize))

	// Debug output for first few records
	if index < 5 {
		fmt.Printf("Debug: Reading MFT record %d at offset 0x%X\n", index, mftOffset)
	}

	// Check if offset is within volume bounds
	if mftOffset >= v.volumeSize {
		return nil, fmt.Errorf("MFT record offset 0x%X exceeds volume size 0x%X", mftOffset, v.volumeSize)
	}

	data := make([]byte, v.mftRecordSize)
	n, err := v.readAt(data, mftOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFT record at offset 0x%X: %v", mftOffset, err)
	}

	if n != int(v.mftRecordSize) {
		return nil, fmt.Errorf("incomplete MFT record read at offset 0x%X: got %d bytes, expected %d",
			mftOffset, n, v.mftRecordSize)
	}

	// Debug output for first few records
	if index < 5 {
		fmt.Printf("Debug: Record %d first 8 bytes: % X\n", index, data[:8])
	}

	// Apply update sequence array fixups
	if err := v.applyFixups(data); err != nil {
		return nil, fmt.Errorf("failed to apply fixups: %v", err)
	}

	// Verify record signature ("FILE")
	if string(data[0:4]) != "FILE" {
		return nil, fmt.Errorf("invalid MFT record signature at offset 0x%X: got %X", mftOffset, data[0:4])
	}

	return data, nil
}

// applyFixups applies the update sequence array fixups to the MFT record
func (v *NTFSVolume) applyFixups(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("record too small for fixups")
	}

	// Get update sequence array offset and size
	usaOffset := binary.LittleEndian.Uint16(data[4:6])
	usaCount := binary.LittleEndian.Uint16(data[6:8])

	// Validate USA parameters
	// Each MFT record is typically 1024 bytes, split into 512-byte sectors
	// usaCount should be (recordSize/sectorSize + 1), including the USN
	expectedCount := uint16(v.mftRecordSize/uint32(v.sectorSize)) + 1
	if usaCount != expectedCount {
		return fmt.Errorf("unexpected USA count: got %d, want %d", usaCount, expectedCount)
	}

	if usaOffset < 42 || int(usaOffset+(usaCount*2)) > len(data) {
		return fmt.Errorf("invalid USA offset %d or count %d", usaOffset, usaCount)
	}

	// Get the update sequence number (first entry in the USA)
	usn := binary.LittleEndian.Uint16(data[usaOffset : usaOffset+2])

	// Apply fixups to each sector
	// Start from 1 because 0 is the USN itself
	for i := uint16(1); i < usaCount; i++ {
		// Calculate sector end position
		sectorEnd := i * uint16(v.sectorSize)
		if int(sectorEnd) > len(data) {
			return fmt.Errorf("sector end %d exceeds record size %d", sectorEnd, len(data))
		}

		// Get the expected end-of-sector value
		endOfSector := binary.LittleEndian.Uint16(data[sectorEnd-2 : sectorEnd])

		// Get the fixup value from the USA
		fixupOffset := usaOffset + (i * 2)
		fixupValue := binary.LittleEndian.Uint16(data[fixupOffset : fixupOffset+2])

		// Verify the end-of-sector matches the USN
		if endOfSector != usn {
			// Some implementations don't use the USN correctly, so we'll just warn
			fmt.Printf("Warning: sector end marker mismatch at sector %d: expected %04X, got %04X\n",
				i, usn, endOfSector)
		}

		// Apply the fixup value
		binary.LittleEndian.PutUint16(data[sectorEnd-2:sectorEnd], fixupValue)
	}

	return nil
}

// ReadBytes reads a specified number of bytes from the volume at the given offset
func (v *NTFSVolume) ReadBytes(offset int64, size int) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("negative offset not allowed")
	}

	if offset+int64(size) > v.volumeSize {
		return nil, fmt.Errorf("read beyond volume size")
	}

	data := make([]byte, size)
	n, err := v.readAt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read bytes: %v", err)
	}

	if n != size {
		return nil, fmt.Errorf("incomplete read: got %d bytes, expected %d", n, size)
	}

	return data, nil
}

// ReadFileContent reads the content of a file from its MFT record
func (v *NTFSVolume) ReadFileContent(file *FileInfo) ([]byte, error) {
	if file == nil {
		return nil, fmt.Errorf("nil file info")
	}

	// Find the data attribute
	var dataAttr *Attribute
	for i := range file.AttrList {
		if file.AttrList[i].Type == ATTR_DATA && file.AttrList[i].Name == "" {
			dataAttr = &file.AttrList[i]
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

	// Allocate buffer for file content
	data := make([]byte, dataAttr.NonResident.RealSize)
	offset := 0

	// Read data runs
	runs, err := parseDataRuns(dataAttr.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data runs: %v", err)
	}

	// Read each run
	for _, run := range runs {
		if run.IsHole {
			// Fill sparse region with zeros
			for i := 0; i < int(run.ClusterCount*uint64(v.clusterSize)); i++ {
				if offset < len(data) {
					data[offset] = 0
					offset++
				}
			}
			continue
		}

		// Read clusters
		clusterData := make([]byte, run.ClusterCount*uint64(v.clusterSize))
		_, err := v.readAt(clusterData, int64(run.StartCluster)*int64(v.clusterSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read cluster data: %v", err)
		}

		// Copy to output buffer
		for i := 0; i < len(clusterData) && offset < len(data); i++ {
			data[offset] = clusterData[i]
			offset++
		}
	}

	return data[:dataAttr.NonResident.RealSize], nil
}

// readNonResidentAttribute reads the data from a non-resident attribute
func (v *NTFSVolume) readNonResidentAttribute(attr *Attribute) ([]byte, error) {
	if attr == nil || attr.NonResident == nil {
		return nil, fmt.Errorf("invalid non-resident attribute")
	}

	// Parse data runs
	runs, err := parseDataRuns(attr.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse data runs: %v", err)
	}

	// Allocate buffer for the entire attribute
	data := make([]byte, attr.NonResident.RealSize)
	offset := int64(0)

	// Read data from each run
	for _, run := range runs {
		if run.IsHole {
			// Fill sparse region with zeros
			for i := int64(0); i < int64(run.ClusterCount*uint64(v.clusterSize)); i++ {
				if offset < int64(attr.NonResident.RealSize) {
					data[offset] = 0
					offset++
				}
			}
			continue
		}

		// Read clusters
		clusterData := make([]byte, run.ClusterCount*uint64(v.clusterSize))
		_, err := v.readAt(clusterData, int64(run.StartCluster)*int64(v.clusterSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read cluster data: %v", err)
		}

		// Copy to output buffer
		for i := range clusterData {
			if offset < int64(attr.NonResident.RealSize) {
				data[offset] = clusterData[i]
				offset++
			}
		}
	}

	return data[:attr.NonResident.RealSize], nil
}
