package protean

import (
	"encoding/json"
	"fmt"
)

// Accepted in serialised form by Configure().
type ProteanConfig struct {
	decompression   DecompressionConfig
	encryption      EncryptionConfig
	fragmentation   FragmentationConfig
	injection       SequenceConfig
	headerInjection HeaderConfig
}

// Creates a sample (non-random) config, suitable for testing.
func sampleProteanConfig() ProteanConfig {
	return ProteanConfig{decompression: sampleDecompressionConfig(), encryption: sampleEncryptionConfig(), fragmentation: sampleFragmentationConfig(), injection: sampleSequenceConfig(), headerInjection: sampleHeaderConfig()}
}

func flatMap(input [][]byte, mappedFunction func([]byte) [][]byte) [][]byte {
	var accum [][]byte
	for _, item := range input {
		mapped := mappedFunction(item)
		if accum == nil {
			accum = mapped
		} else {
			accum = append(accum, mapped...)
		}
	}

	return accum
}

// A packet shaper that composes multiple Transformers.
// The following Transformers are composed:
// - Fragmentation based on MTU and chunk size
// - AES encryption
// - decompression using arithmetic coding
// - byte sequence injection
type ProteanShaper struct {
	// Fragmentation Transformer
	fragmenter *FragmentationShaper

	// Encryption Transformer
	encrypter *EncryptionShaper

	// Decompression Transformer
	decompressor *DecompressionShaper

	// Byte sequence injecter Transformer
	injecter *ByteSequenceShaper

	// Byte sequence injecter Transformer
	headerinjecter *HeaderShaper
}

func NewProteanShaper() *ProteanShaper {
	shaper := &ProteanShaper{}
	config := sampleProteanConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	shaper.Configure(string(jsonConfig))
	return shaper
}

// This method is required to implement the Transformer API.
// @param {[]byte} key Key to set, not used by this class.
func (shaper *ProteanShaper) SetKey(key []byte) {
}

// Configure the Transformer with the headers to inject and the headers
// to remove.
func (this *ProteanShaper) Configure(jsonConfig string) {
	var proteanConfig ProteanConfig
	err := json.Unmarshal([]byte(jsonConfig), &proteanConfig)
	if err != nil {
		fmt.Println("Encryption shaper requires key parameter")
	}

	// Required parameters:
	// - decompression
	// - encryption
	// - fragmentation
	// - injection
	// - headerInjection

	this.decompressor = NewDecompressionShaper()
	this.encrypter = NewEncryptionShaper()
	this.injecter = NewByteSequenceShaper()
	this.headerinjecter = NewHeaderShaper()
	this.fragmenter = NewFragmentationShaper()

	this.decompressor.ConfigureStruct(proteanConfig.decompression)
	this.encrypter.ConfigureStruct(proteanConfig.encryption)
	this.injecter.ConfigureStruct(proteanConfig.injection)
	this.headerinjecter.ConfigureStruct(proteanConfig.headerInjection)
	this.fragmenter.ConfigureStruct(proteanConfig.fragmentation)
}

// Apply the following Transformations:
// - Fragment based on MTU and chunk size
// - Encrypt using AES
// - Decompress using arithmetic coding
// - Inject headers into packets
// - Inject packets with byte sequences
func (this *ProteanShaper) Transform(buffer []byte) [][]byte {
	// This Transform performs the following steps:
	// - Generate a new random CHUNK_SIZE-byte IV for every packet
	// - Encrypt the packet contents with the random IV and symmetric key
	// - Concatenate the IV and encrypted packet contents
	source := [][]byte{buffer}
	fragmented := flatMap(source, this.fragmenter.Transform)
	encrypted := flatMap(fragmented, this.encrypter.Transform)
	decompressed := flatMap(encrypted, this.decompressor.Transform)
	headerInjected := flatMap(decompressed, this.headerinjecter.Transform)
	injected := flatMap(headerInjected, this.injecter.Transform)
	return injected
}

// Apply the following Transformations:
// - Discard injected packets
// - Discard injected headers
// - Decrypt with AES
// - Compress with arithmetic coding
// - Attempt defragmentation
func (this *ProteanShaper) Restore(buffer []byte) [][]byte {
	// This Restore performs the following steps:
	// - Split the first CHUNK_SIZE bytes from the rest of the packet
	//     The two parts are the IV and the encrypted packet contents
	// - Decrypt the encrypted packet contents with the IV and symmetric key
	// - Return the decrypted packet contents
	source := [][]byte{buffer}
	extracted := flatMap(source, this.injecter.Restore)
	headerExtracted := flatMap(extracted, this.headerinjecter.Restore)
	decompressed := flatMap(headerExtracted, this.decompressor.Restore)
	decrypted := flatMap(decompressed, this.encrypter.Restore)
	defragmented := flatMap(decrypted, this.fragmenter.Restore)
	return defragmented
}

// No-op (we have no state or any resources to Dispose).
func (shaper *ProteanShaper) Dispose() {
}
