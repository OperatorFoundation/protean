package protean

import (
	"encoding/hex"
	"fmt"
	"time"
)

// Cache expiration is set to 60 seconds.
const CACHE_EXPIRATION_TIME time.Duration = time.Duration(60 * 1000)

// Tracks the fragments for a single packet identifier
type PacketTracker struct {
	// Indexed lists of fragments for this packet
	Pieces [][]byte

	// Counts of the number remaining
	// This is an optimization to avoid scanning Pieces repeatedly for counts.
	Counter uint8

	// Stores the Timer objects for expiring each identifier
	// See RFC 815, section 7, paragraph 2 (p. 8)
	Timer *time.Timer
}

// The Defragmenter gathers fragmented packets in a buffer and defragments them.
// The cache expiration strategy is taken from RFC 815: IP Datagram Reassembly
// Algorithms.
type Defragmenter struct {
	// Associates packet identifiers with indexed lists of fragments
	// The packet identifiers are converted from []bytes to hex strings so
	// that they can be used as map keys.
	tracker map[string]PacketTracker

	// Stores the packet identifiers for which we have all fragments
	complete [][][]byte
}

// Add a fragment that has been received from the network.
// Fragments are processed according to the following logic:
//   If the packet identifier is recognized:
//     If we have a fragment for this index:
//       This fragment is a duplicate, drop it.
//     Else:
//      This fragment a new fragment for an existing packet
//   Else:
//     This fragment a new fragment for a new packet.
func (this *Defragmenter) AddFragment(fragment *Fragment) {
	// Convert []byte to hex string so that it can be used as a map key
	hexid := hex.EncodeToString(fragment.Id)

	if tracked, ok := this.tracker[hexid]; ok {
		// A fragment for an existing packet

		// Get list of fragment contents for this packet identifier
		fragmentList := tracked.Pieces
		if fragmentList[fragment.Index] != nil {
			// Duplicate fragment

			// The fragmentation system does not retransmit dropped packets.
			// Therefore, a duplicate is an error.
			// However, it might be a recoverable error.
			// So let's log it and continue.
			fmt.Println("Duplicate fragment %1: %2 / %3", hexid, fragment.Index, fragment.Count)
		} else {
			// New fragment for an existing packet

			// Only the payload is stored explicitly.
			// The other information is stored implicitly in the data structure.
			fragmentList[fragment.Index] = fragment.Payload
			tracked.Pieces = fragmentList

			// Decrement the Counter for this packet identifier
			tracked.Counter = tracked.Counter - 1

			this.tracker[hexid] = tracked

			// If we have all fragments for this packet identifier, it is complete.
			if this.tracker[hexid].Counter == 0 {
				// Extract the completed packet fragments from the tracker
				this.complete = append(this.complete, this.tracker[hexid].Pieces)

				// Stop the Timer now that the packet is complete
				tracked.Timer.Stop()

				// Delete the completed packet from the tracker
				delete(this.tracker, hexid)
			}
		}
	} else {
		// A new fragment for a new packet

		// Make an empty list of fragments.
		fragmentList := make([][]byte, fragment.Count)

		// Store this fragment in the fragment list.
		fragmentList[fragment.Index] = fragment.Payload

		// Set the Counter to the total number of fragments expected.
		// The decrement it as we have already received one fragment.
		var counter = fragment.Count - 1

		if counter == 0 {
			// Deal with the case where there is only one fragment for this packet.
			this.complete = append(this.complete, fragmentList)
		} else {
			// Store time the first fragment arrived, to set the cache expiration.
			// See RFC 815, section 7, paragraph 2 (p. 8)
			// Cache expiration is set to 60 seconds.
			var timer = time.AfterFunc(CACHE_EXPIRATION_TIME, func() { this.reap(hexid) })

			// Store the fragment information in the tracker
			this.tracker[hexid] = PacketTracker{Pieces: fragmentList, Counter: counter, Timer: timer}
		}
	}
}

// Returns the number of packets for which all fragments have arrived.
func (this *Defragmenter) CompleteCount() int {
	return len(this.complete)
}

// Return an []byte for each packet where all fragments are available.
// Calling this clears the set of stored completed fragments.
func (this *Defragmenter) GetComplete() [][]byte {
	var packets [][]byte

	for i := 0; i < len(this.complete); i++ {
		// Obtain the contents from the fragments for a completed packet
		// Get the last elemnet of the list
		fragmentList := this.complete[len(this.complete)-1]
		// Remove the last element of the list
		this.complete = this.complete[:len(this.complete)-1]

		// Assemble the fragment contents into one []byte per packet
		if fragmentList != nil && len(fragmentList) > 0 {
			var packet []byte
			for _, fragment := range fragmentList {
				packet = append(packet, fragment...)
			}

			packets = append(packets, packet)
		}
	}

	return packets
}

func (this *Defragmenter) reap(hexid string) {
	// Remove the fragments from the cache now that the packet has expired
	delete(this.tracker, hexid)
}
