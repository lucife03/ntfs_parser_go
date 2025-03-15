package ntfs

import "fmt"

// DataRun represents a contiguous run of clusters
type DataRun struct {
	StartCluster int64  // Starting cluster number (relative to previous run)
	ClusterCount uint64 // Number of clusters in this run
	IsHole       bool   // True if this is a sparse or unallocated run
}

// parseDataRuns parses the data runs from a non-resident attribute
func parseDataRuns(data []byte) ([]DataRun, error) {
	var runs []DataRun
	offset := 0

	for offset < len(data) {
		// Read header byte
		if data[offset] == 0 {
			break // End of data runs
		}

		lengthSize := int(data[offset] & 0x0F)
		offsetSize := int((data[offset] >> 4) & 0x0F)
		offset++

		if offset+lengthSize+offsetSize > len(data) {
			return nil, fmt.Errorf("data run truncated")
		}

		// Read cluster count (length)
		var clusterCount uint64
		for i := 0; i < lengthSize; i++ {
			clusterCount |= uint64(data[offset+i]) << uint(i*8)
		}
		offset += lengthSize

		// Read cluster offset (relative to previous run)
		var startCluster int64
		if offsetSize > 0 {
			// Handle signed offset
			var rawOffset uint64
			for i := 0; i < offsetSize; i++ {
				rawOffset |= uint64(data[offset+i]) << uint(i*8)
			}

			// Sign extend if negative
			if data[offset+offsetSize-1]&0x80 != 0 {
				rawOffset |= ^uint64(0) << uint(offsetSize*8)
			}
			startCluster = int64(rawOffset)
		}
		offset += offsetSize

		runs = append(runs, DataRun{
			StartCluster: startCluster,
			ClusterCount: clusterCount,
			IsHole:       startCluster == 0,
		})
	}

	return runs, nil
}

// readDataRuns reads the data from a series of data runs
func (v *NTFSVolume) readDataRuns(runs []DataRun, size uint64) ([]byte, error) {
	data := make([]byte, size)
	var dataOffset uint64
	var currentLCN int64

	for _, run := range runs {
		if run.IsHole {
			// Fill sparse region with zeros
			for i := uint64(0); i < run.ClusterCount*uint64(v.clusterSize) && dataOffset < size; i++ {
				data[dataOffset] = 0
				dataOffset++
			}
			continue
		}

		// Calculate absolute LCN
		currentLCN += run.StartCluster
		if currentLCN < 0 {
			return nil, fmt.Errorf("negative cluster number")
		}

		// Read clusters
		offset := v.partitionOffset + int64(currentLCN)*int64(v.clusterSize)
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
