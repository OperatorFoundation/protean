package protean

import (
	"encoding/json"
	"fmt"
)

type DecompressionConfig struct {
	Frequencies []uint32
}

// Creates a sample (non-random) config, suitable for testing.
func sampleDecompressionConfig() DecompressionConfig {
	probs := make([]uint32, 256)
	for index := 0; index < 256; index++ {
		probs[index] = 1
	}

	return DecompressionConfig{Frequencies: probs}
}

// A Transformer that uses an arithmetic coder to change the entropy.
// This Transformer uses a somewhat unusual technique of reverse compression.
// The only instance I know of this being done previously is in Dust:
// http://github.com/blanu/Dust
//
// Dust uses the reverse Huffman encoding describe in the book "Disappearing
// Cryptography" by Peter Wayner. Chapter 6.2 (p. 88) describes the technique
// as follows:
// "This chapter is about creating an automatic way of taking small, innocuous
// bits of data and embellishing them with deep, embroidered details until the
// result mimics something completely different. The data is hidden as it
// assumes this costume. The effect is accomplished here by running the Huffman
// compression algorithm described in Chapter 5 in reverse. Ordinarily, the
// Huffman algorithm would aprrxoimate the statistical distribution of the text
// and then convert it into a digital shorthand. Running this in reverse can
// take normal data and form it into elaborate patterns."
//
// Dust uses a Huffman encoder, and statistical tests run on the results have
// shown that Huffman encoding has a limitation when used in this way. The
// probabilities of bytes can only be based on powers of two (1/2, 1/4, etc.).
// This limits its facility at mimicry if the mimicked distribution differs
// greatly from an approximation which is quantized into powers of two.
// Therefore, an arithmetic encoder is used here instead of a Huffman encoder.
// As far as I know, this is the first time this has been done, so the results
// compared to Huffman encoding are unknown.
//
// The important thing to realize is that the compression algorithm is being
// run in reverse, contrary to normal expectations.
type DecompressionShaper struct {
	//implements Transformer

	Frequencies []uint32

	encoder Encoder

	decoder Decoder
}

func NewDecompressionShaper() *DecompressionShaper {
	shaper := &DecompressionShaper{}
	config := sampleDecompressionConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	shaper.Configure(string(jsonConfig))
	return shaper
}

// This method is required to implement the Transformer API.
// @param {[]byte} key Key to set, not used by this class.
func (shaper *DecompressionShaper) SetKey(key []byte) {
}

// Configure the Transformer with the headers to inject and the headers
// to remove.
func (this *DecompressionShaper) Configure(jsonConfig string) {
	var config DecompressionConfig
	err := json.Unmarshal([]byte(jsonConfig), &config)
	if err != nil {
		fmt.Println("Decompression shaper requires key parameter")
	}

	this.ConfigureStruct(config)
}

func (this *DecompressionShaper) ConfigureStruct(config DecompressionConfig) {
	this.Frequencies = config.Frequencies
	this.encoder = NewEncoder(this.Frequencies)
	this.decoder = NewDecoder(this.Frequencies)
}

// Decompress the bytestream. The purpose of this Transform is to take a high
// entropy bytestream and produce a lower entropy one.
func (shaper *DecompressionShaper) Transform(buffer []byte) [][]byte {
	// The purpose of this section of code is to encode the data in the format
	// expected by the decoder. This format is inherited from the original
	// psuedocode implementation in the range encoding paper.
	// The decoder expects data to be in the following format:
	// - header - 1 byte
	// - data - variable
	// - footer - 2 bytes
	// - length - 2 bytes

	// Create a header byte. This is an arbitrary value that is required but
	// ignored by the decoder. A non-zero value is used to simplify debugging.
	header := encodeByte(0xCA)
	// Create some trailing zero bytes. These are consumed by the decoder.
	footer := make([]byte, 2)
	// Create an encoded length. This is required but ignored by the decoder.
	length := encodeShort(uint16(len(buffer)))
	// Construct an encoded buffer if the form expected by the decoder.
	encoded := append(header, buffer...)
	encoded = append(encoded, footer...)
	encoded = append(encoded, length...)

	// Use a decoder to decompress.
	// This is backwards from what you'd normally expect.
	// The decoded bytes will have two trailing zeros added, so these are
	// sliced off.
	decoded := shaper.decoder.Decode(encoded)
	decoded = decoded[:len(decoded)-2]
	return [][]byte{decoded}
}

func (shaper *DecompressionShaper) Restore(buffer []byte) [][]byte {
	// Use an encoder to compress.
	// This is backwards from what you'd normally expect.
	encoded := shaper.encoder.Encode(buffer)
	// The encoder generates data to be in the following format:
	// - header - 1 byte
	// - data - variable
	// - footer - 2 bytes
	// - length - 2 bytes
	// Slice off the extra bytes and only return the data.
	return [][]byte{encoded[1 : len(encoded)-4]}
}

// No-op (we have no state or any resources to Dispose).
func (shaper *DecompressionShaper) Dispose() {
}
