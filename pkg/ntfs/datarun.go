package ntfs

import "fmt"

// DataRun represents a contiguous run of clusters
type DataRun struct {
	StartCluster uint64 // Starting cluster number (absolute)
	ClusterCount uint64 // Number of clusters in this run
	IsHole       bool   // True if this is a sparse or unallocated run
}

// parseDataRuns parses the data runs from a non-resident attribute
func parseDataRuns(data []byte) ([]DataRun, error) {
	if data == nil || len(data) == 0 {
		return nil, fmt.Errorf("empty data runs")
	}

	// Debug the first 16 bytes of data runs
	fmt.Printf("Debug: Data runs first %d bytes: % X\n", min(16, len(data)), data[:min(16, len(data))])

	runs := make([]DataRun, 0)
	offset := 0
	var lastCluster uint64

	for offset < len(data) {
		if data[offset] == 0 {
			// End of data runs
			break
		}

		// The first byte contains the length bytes and offset bytes
		header := data[offset]
		lengthBytes := int(header & 0x0F)
		offsetBytes := int((header >> 4) & 0x0F)

		fmt.Printf("Debug: Data run header: 0x%02X (length bytes: %d, offset bytes: %d)\n",
			header, lengthBytes, offsetBytes)

		// Bounds check
		if offset+1+lengthBytes+offsetBytes > len(data) {
			return nil, fmt.Errorf("data run extends beyond buffer")
		}

		// Read the run length (number of clusters)
		runLength := uint64(0)
		for i := 0; i < lengthBytes; i++ {
			runLength |= uint64(data[offset+1+i]) << (i * 8)
		}

		// Read the run offset (relative to previous run)
		var runOffset int64 = 0
		for i := 0; i < offsetBytes; i++ {
			runOffset |= int64(data[offset+1+lengthBytes+i]) << (i * 8)
		}

		// Handle negative offsets (sign extension)
		if offsetBytes > 0 && runOffset > 0 && (data[offset+1+lengthBytes+offsetBytes-1]&0x80) != 0 {
			// Sign extend negative numbers
			runOffset |= -1 << (offsetBytes * 8)
		}

		// Calculate absolute cluster
		var startCluster uint64
		if runOffset == 0 {
			// Sparse run (hole)
			fmt.Printf("Debug: Found sparse run (hole) of %d clusters\n", runLength)
			startCluster = 0
		} else {
			// Need to carefully handle sign
			if runOffset < 0 {
				// Handle negative offset
				if uint64(-runOffset) > lastCluster {
					return nil, fmt.Errorf("negative offset exceeds last cluster position")
				}
				startCluster = lastCluster - uint64(-runOffset)
			} else {
				// Handle positive offset
				startCluster = lastCluster + uint64(runOffset)
			}
			lastCluster = startCluster
		}

		run := DataRun{
			StartCluster: startCluster,
			ClusterCount: runLength,
			IsHole:       runOffset == 0,
		}

		fmt.Printf("Debug: Data run: StartCluster=%d, ClusterCount=%d, IsHole=%v\n",
			run.StartCluster, run.ClusterCount, run.IsHole)

		runs = append(runs, run)
		offset += 1 + lengthBytes + offsetBytes
	}

	return runs, nil
}

// readDataRuns reads the data from a series of data runs
func (v *NTFSVolume) readDataRuns(runs []DataRun, size uint64) ([]byte, error) {
	data := make([]byte, size)
	var dataOffset uint64

	for _, run := range runs {
		if run.IsHole {
			// Fill sparse region with zeros
			for i := uint64(0); i < run.ClusterCount*uint64(v.clusterSize) && dataOffset < size; i++ {
				data[dataOffset] = 0
				dataOffset++
			}
			continue
		}

		// Read clusters using absolute LCN
		offset := v.partitionOffset + int64(run.StartCluster)*int64(v.clusterSize)
		runSize := run.ClusterCount * uint64(v.clusterSize)
		if dataOffset+runSize > size {
			runSize = size - dataOffset
		}

		n, err := v.readAt(data[dataOffset:dataOffset+runSize], offset)
		if err != nil {
			return nil, fmt.Errorf("failed to read data run: %v", err)
		}
		if uint64(n) != runSize {
			return nil, fmt.Errorf("incomplete data run read")
		}

		dataOffset += runSize
		if dataOffset >= size {
			break
		}
	}

	return data[:size], nil
}
