package protean

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Accepted in serialised form by Configure().
type SequenceConfig struct {
	// Sequences that should be added to the outgoing packet stream.
	AddSequences []SerializedSequenceModel

	// Sequences that should be removed from the incoming packet stream.
	RemoveSequences []SerializedSequenceModel
}

// Sequence models where the Sequences have been encoded as strings.
// This is used by the SequenceConfig argument passed to Configure().
type SerializedSequenceModel struct {
	// Index of the packet into the Sequence.
	Index int8

	// Offset of the Sequence in the packet.
	Offset int16

	// Byte Sequence encoded as a string.
	Sequence string

	// Target packet Length.
	Length int16
}

// Sequence models where the Sequences have been decoded as []bytes.
// This is used internally by the ByteSequenceShaper.
type SequenceModel struct {
	// Index of the packet into the stream.
	Index int8

	// Offset of the Sequence in the packet.
	Offset int16

	// Byte Sequence.
	Sequence []byte

	// Target packet Length.
	Length int16
}

// Creates a sample (non-random) config, suitable for testing.
func sampleSequenceConfig() SequenceConfig {
	var bytes = []byte("OH HELLO")
	hexSequence := hex.EncodeToString(bytes)
	sequenceModel := SerializedSequenceModel{Index: 0, Offset: 0, Sequence: hexSequence, Length: 256}
	return SequenceConfig{AddSequences: []SerializedSequenceModel{sequenceModel}, RemoveSequences: []SerializedSequenceModel{sequenceModel}}
}

// An obfuscator that injects byte sequences.
type ByteSequenceShaper struct {
	// Sequences that should be added to the outgoing packet stream.
	AddSequences []*SequenceModel

	// Sequences that should be removed from the incoming packet stream.
	RemoveSequences []*SequenceModel

	// Index of the first packet to be injected into the stream.
	FirstIndex int8

	// Index of the last packet to be injected into the stream.
	LastIndex int8

	// Current Index into the output stream.
	// This starts at zero and is incremented every time a packet is output.
	// The OutputIndex is compared to the SequenceModel Index. When they are
	// equal, a byte Sequence packet is injected into the output.
	OutputIndex int8
}

func NewByteSequenceShaper() *ByteSequenceShaper {
	shaper := &ByteSequenceShaper{}
	config := sampleSequenceConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	shaper.Configure(string(jsonConfig))
	return shaper
}

// This method is required to implement the Transformer API.
// @param {[]byte} key Key to set, not used by this class.
func (shaper *ByteSequenceShaper) SetKey(key []byte) {
}

// Configure the Transformer with the headers to inject and the headers
// to remove.
func (shaper *ByteSequenceShaper) Configure(jsonConfig string) {
	var config SequenceConfig
	err := json.Unmarshal([]byte(jsonConfig), &config)
	if err != nil {
		fmt.Println("Encryption shaper requires key parameter")
	}

	shaper.ConfigureStruct(config)
}

func (shaper *ByteSequenceShaper) ConfigureStruct(config SequenceConfig) {
	shaper.AddSequences, shaper.RemoveSequences = deserializeByteSequenceConfig(config)

	// Make a note of the Index of the first packet to inject
	shaper.FirstIndex = shaper.AddSequences[0].Index

	// Make a note of the Index of the last packet to inject
	shaper.LastIndex = shaper.AddSequences[len(shaper.AddSequences)-1].Index
}

// Decode the key from string in the config information
func deserializeByteSequenceConfig(config SequenceConfig) ([]*SequenceModel, []*SequenceModel) {
	adds := make([]*SequenceModel, len(config.AddSequences))
	rems := make([]*SequenceModel, len(config.RemoveSequences))

	for x, seq := range config.AddSequences {
		adds[x] = deserializeByteSequenceModel(seq)
	}

	for x, seq := range config.RemoveSequences {
		rems[x] = deserializeByteSequenceModel(seq)
	}

	return adds, rems
}

// Decode the header from a string in the header model
func deserializeByteSequenceModel(model SerializedSequenceModel) *SequenceModel {
	sequence, err := hex.DecodeString(model.Sequence)
	if err != nil {
		return nil
	}

	return &SequenceModel{Index: model.Index, Offset: model.Offset, Sequence: sequence, Length: model.Length}
}

// Inject header.
func (shaper *ByteSequenceShaper) Transform(buffer []byte) [][]byte {
	var results [][]byte

	// Check if the current Index into the packet stream is within the range
	// where a packet injection could possibly occur.
	if shaper.OutputIndex <= shaper.LastIndex {
		// Injection has not finished, but may not have started yet.
		if shaper.OutputIndex >= shaper.FirstIndex {
			// Injection has started and has not finished, so check to see if it is
			// time to inject a packet.

			// Inject fake packets before the real packet
			results = shaper.Inject(results)

			// Inject the real packet
			results = shaper.OutputAndIncrement(results, buffer)

			//Inject fake packets after the real packet
			results = shaper.Inject(results)
		} else {
			// Injection has not started yet. Keep track of the Index.
			results = shaper.OutputAndIncrement(results, buffer)
		}

		return results
	} else {
		// Injection has finished and will not occur again. Take the fast path and
		// just return the buffer.
		return [][]byte{buffer}
	}
}

// Remove injected packets.
func (shaper *ByteSequenceShaper) Restore(buffer []byte) [][]byte {
	match := shaper.findMatchingPacket(buffer)
	if match != nil {
		return [][]byte{}
	} else {
		return [][]byte{buffer}
	}
}

// No-op (we have no state or any resources to Dispose).
func (shaper *ByteSequenceShaper) Dispose() {
}

// Inject packets
func (shaper *ByteSequenceShaper) Inject(results [][]byte) [][]byte {
	nextPacket := shaper.findNextPacket(shaper.OutputIndex)
	for nextPacket != nil {
		results = shaper.OutputAndIncrement(results, shaper.makePacket(nextPacket))
		nextPacket = shaper.findNextPacket(shaper.OutputIndex)
	}

	return results
}

func (shaper *ByteSequenceShaper) OutputAndIncrement(results [][]byte, result []byte) [][]byte {
	results = append(results, result)
	shaper.OutputIndex = shaper.OutputIndex + 1
	return results
}

// For an Index into the packet stream, see if there is a Sequence to inject.
func (shaper *ByteSequenceShaper) findNextPacket(index int8) *SequenceModel {
	for _, sequence := range shaper.AddSequences {
		if index == sequence.Index {
			return sequence
		}
	}

	return nil
}

// For a byte Sequence, see if there is a matching Sequence to remove.
func (shaper *ByteSequenceShaper) findMatchingPacket(sequence []byte) *SequenceModel {
	for i, model := range shaper.RemoveSequences {
		target := model.Sequence
		source := sequence[int(model.Offset) : int(model.Offset)+len(target)]
		if bytes.Equal(source, target) {
			// Remove matched packet so that it's not matched again
			shaper.RemoveSequences = append(shaper.RemoveSequences[:i], shaper.RemoveSequences[i+1:]...)

			// Return matched packet
			return model
		}
	}

	return nil
}

// With a Sequence model, generate a packet to inject into the stream.
func (shaper *ByteSequenceShaper) makePacket(model *SequenceModel) []byte {
	var result []byte

	// Add the bytes before the Sequence.
	if model.Offset > 0 {
		length := model.Offset
		randomBytes := make([]byte, length)
		rand.Read(randomBytes)
		result = append(result, randomBytes...)
	}

	// Add the Sequence
	result = append(result, model.Sequence...)

	// Add the bytes after the sequnece
	if model.Offset < model.Length {
		length := int(model.Length) - (int(model.Offset) + len(model.Sequence))
		randomBytes := make([]byte, length)
		rand.Read(randomBytes)
		result = append(result, randomBytes...)
	}

	return result
}
