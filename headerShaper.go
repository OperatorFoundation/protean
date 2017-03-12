package protean

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Accepted in serialised form by Configure().
type HeaderConfig struct {
	// Header that should be added to the beginning of each outgoing packet.
	AddHeader SerializedHeaderModel

	// Header that should be removed from each incoming packet.
	RemoveHeader SerializedHeaderModel
}

// Header models where the headers have been encoded as strings.
// This is used by the HeaderConfig argument passed to Configure().
type SerializedHeaderModel struct {
	// Header encoded as a string.
	Header string
}

// Header models where the headers have been decoded as []bytes.
// This is used internally by the HeaderShaper.
type HeaderModel struct {
	// Header.
	Header []byte
}

// Creates a sample (non-random) config, suitable for testing.
func sampleHeaderConfig() HeaderConfig {
	var buffer = []byte("\x41\x02")
	hexHeader := hex.EncodeToString(buffer)
	var header = SerializedHeaderModel{Header: hexHeader}

	return HeaderConfig{AddHeader: header, RemoveHeader: header}
}

// An obfuscator that injects headers.
type HeaderShaper struct {
	// Headers that should be added to the outgoing packet stream.
	AddHeader HeaderModel

	// Headers that should be removed from the incoming packet stream.
	RemoveHeader HeaderModel
}

func NewHeaderShaper() *HeaderShaper {
	headerShaper := &HeaderShaper{}
	config := sampleHeaderConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	headerShaper.Configure(string(jsonConfig))
	return headerShaper
}

// This method is required to implement the Transformer API.
// @param {[]byte} key Key to set, not used by this class.
func (headerShaper *HeaderShaper) SetKey(key []byte) {
}

// Configure the Transformer with the headers to inject and the headers
// to remove.
func (headerShaper *HeaderShaper) Configure(jsonConfig string) {
	var config HeaderConfig
	err := json.Unmarshal([]byte(jsonConfig), &config)
	if err != nil {
		fmt.Println("Header shaper requires addHeader and removeHeader parameters")
	}

	headerShaper.ConfigureStruct(config)
}

func (headerShaper *HeaderShaper) ConfigureStruct(config HeaderConfig) {
	headerShaper.AddHeader, headerShaper.RemoveHeader = deserializeConfig(config)
}

// Inject header.
func (headerShaper *HeaderShaper) Transform(buffer []byte) [][]byte {
	//    log.debug('->', arraybuffers.arrayBufferToHexString(buffer))
	//    log.debug('>>', arraybuffers.arrayBufferToHexString(
	//      arraybuffers.concat([this.addHeader_.header, buffer])
	//    ))
	return [][]byte{append(headerShaper.AddHeader.Header, buffer...)}
}

// Remove injected header.
func (headerShaper *HeaderShaper) Restore(buffer []byte) [][]byte {
	//    log.debug('<-', arraybuffers.arrayBufferToHexString(buffer))
	headerLength := len(headerShaper.RemoveHeader.Header)
	header := buffer[0:headerLength]
	payload := buffer[headerLength:]

	if bytes.Equal(header, headerShaper.RemoveHeader.Header) {
		// Remove the injected header.
		//      log.debug('<<', arraybuffers.arrayBufferToHexString(payload))
		return [][]byte{payload}
	} else {
		// Injected header not found, so return the unmodified packet.
		//      log.debug('Header not found')
		return [][]byte{buffer}
	}
}

// No-op (we have no state or any resources to Dispose).
func (headerShaper *HeaderShaper) Dispose() {
}

// Decode the headers from strings in the config information
func deserializeConfig(config HeaderConfig) (HeaderModel, HeaderModel) {
	return deserializeModel(config.AddHeader), deserializeModel(config.RemoveHeader)
}

// Decode the header from a string in the header model
func deserializeModel(model SerializedHeaderModel) HeaderModel {
	config, _ := hex.DecodeString(string(model.Header))
	return HeaderModel{Header: config}
}
