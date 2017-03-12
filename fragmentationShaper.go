package protean

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// Accepted in serialised form by Configure().
type FragmentationConfig struct {
	MaxLength uint16
}

// Creates a sample (non-random) config, suitable for testing.
func sampleFragmentationConfig() FragmentationConfig {
	return FragmentationConfig{MaxLength: 1440}
}

// A Transformer that enforces a maximum packet length.
type FragmentationShaper struct {
	maxLength uint16

	fragmentBuffer *Defragmenter
}

func NewFragmentationShaper() *FragmentationShaper {
	shaper := &FragmentationShaper{}
	config := sampleFragmentationConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	shaper.Configure(string(jsonConfig))
	return shaper
}

// This method is required to implement the Transformer API.
// @param {[]byte} key Key to set, not used by this class.
func (shaper *FragmentationShaper) SetKey(key []byte) {
}

// Configure the Transformer with the headers to inject and the headers
// to remove.
func (shaper *FragmentationShaper) Configure(jsonConfig string) {
	var config FragmentationConfig
	err := json.Unmarshal([]byte(jsonConfig), &config)
	if err != nil {
		fmt.Println("Fragmentation shaper requires key parameter")
	}

	shaper.ConfigureStruct(config)
}

func (shaper *FragmentationShaper) ConfigureStruct(config FragmentationConfig) {
	shaper.maxLength = config.MaxLength
	shaper.fragmentBuffer = &Defragmenter{}
}

// Perform the following steps:
// - Break buffer into one or more fragments
// - Add fragment headers to each fragment
// - Add fill if necessary to pad each fragment to a multiple of CHUNK_SIZE
// - Encode fragments into new buffers
func (this *FragmentationShaper) Transform(buffer []byte) [][]byte {
	var fragmentList = this.makeFragments(buffer)
	var results [][]byte

	for _, fragment := range fragmentList {
		var result = encodeFragment(fragment)
		results = append(results, result)
	}

	return results
}

// Perform the following steps:
// - Decode buffer into a fragment
// - Remove fill
// - Remove fragment headers
// - Attempt to defragment, yielding zero or more new buffers
func (this *FragmentationShaper) Restore(buffer []byte) [][]byte {
	fragment, err := decodeFragment(buffer)
	if err != nil {
		return nil
	}

	this.fragmentBuffer.AddFragment(fragment)
	if this.fragmentBuffer.CompleteCount() > 0 {
		var complete = this.fragmentBuffer.GetComplete()
		return complete
	} else {
		return [][]byte{}
	}
}

// No-op (we have no state or any resources to Dispose).
func (shaper *FragmentationShaper) Dispose() {
}

// Perform the following steps:
// - Break buffer into one or more fragments
// - Add fragment headers to each fragment
// - Add fill if necessary to pad each fragment to a multiple of CHUNK_SIZE
func (this *FragmentationShaper) makeFragments(buffer []byte) []Fragment {
	payloadSize := len(buffer) + HEADER_SIZE + IV_SIZE
	fillSize := CHUNK_SIZE - (payloadSize % CHUNK_SIZE)
	packetSize := payloadSize + fillSize

	if packetSize <= int(this.maxLength) {
		var fill = make([]byte, fillSize)
		if fillSize > 0 {
			rand.Read(fill)
		}

		// One fragment
		fragment := Fragment{Length: uint16(len(buffer)), Id: makeRandomId(), Index: 0, Count: 1, Payload: buffer, Padding: fill}

		return []Fragment{fragment}
	} else {
		// Multiple fragments
		firstLength := int(this.maxLength) - (HEADER_SIZE + IV_SIZE + fillSize)
		//		restLength := len(buffer) - firstLength
		first := this.makeFragments(buffer[:firstLength])
		rest := this.makeFragments(buffer[:firstLength])
		fragmentList := append(first, rest...)

		return fixFragments(fragmentList)
	}
}

// Rewrite the fragments to impose the following constraints:
// - All fragments have the same id
// - Each fragment has a unique, incremental index
// - All fragments have the same, correct count
func fixFragments(fragmentList []Fragment) []Fragment {
	var id = fragmentList[0].Id
	var count = len(fragmentList)

	for index, _ := range fragmentList {
		fragmentList[index].Id = id
		fragmentList[index].Index = uint8(index)
		fragmentList[index].Count = uint8(count)
	}

	return fragmentList
}
