package protean

import (
	"crypto/rand"
	"errors"
)

// Header size: length + id + fragment number + total number
const HEADER_SIZE int = 2 + 32 + 1 + 1

// A Fragment represents a piece of a packet when fragmentation has occurred.
type Fragment struct {
	Length  uint16
	Id      []byte
	Index   uint8
	Count   uint8
	Payload []byte
	Padding []byte
}

// Make a random 32-byte identifier for the packet fragment.
// This should be unique, or else defragmentation breaks.
// A 32-byte size was chosen as this is a common hash function output size.
// In the future, a hash could perhaps be used instead of a random identifier.
func makeRandomId() []byte {
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	return randomBytes
}

// Deserialize the content of a packet into a Fragment object
// The Fragment format is as follows:
//   - length of the payload, 2 bytes
//   - id, 32 bytes
//   - fragment number, 1 byte
//   - total number of fragments for this id, 1 byte
//   - payload, number of bytes specified by length field
//   - padding, variable number of bytes, whatever is left after the payload
func decodeFragment(buffer []byte) (*Fragment, error) {
	lengthBytes := buffer[0:2]
	fragmentId := buffer[2:34]
	fragmentNumber := buffer[34:35]
	totalNumber := buffer[35:36]
	remaining := buffer[36:]

	var length = decodeShort(lengthBytes)

	var payload []byte
	var padding []byte

	if len(remaining) > int(length) {
		payload = remaining[:length]
		padding = remaining[length:]
	} else if len(buffer) == int(length) {
		payload = remaining
		padding = []byte{}
	} else {
		// buffer.byteLength < length
		return nil, errors.New("Fragment could not be decoded, shorter than length")
	}

	return &Fragment{Length: length, Id: fragmentId, Index: decodeByte(fragmentNumber), Count: decodeByte(totalNumber), Payload: payload, Padding: padding}, nil
}

// Serialize a Fragment object so that it can be sent as a packet
// The Fragment format is as follows:
//   - length of the payload, 2 bytes
//   - id, 32 bytes
//   - fragment number, 1 byte
//   - total number of fragments for this id, 1 byte
//   - payload, number of bytes specified by length field
//   - padding, variable number of bytes, whatever is left after the payload
func encodeFragment(fragment Fragment) []byte {
	var result []byte

	result = append(result, encodeShort(fragment.Length)...)
	result = append(result, fragment.Id...)
	result = append(result, encodeByte(fragment.Index)...)
	result = append(result, encodeByte(fragment.Count)...)
	result = append(result, fragment.Payload...)
	result = append(result, fragment.Padding...)

	return result
}

func encodeByte(b uint8) []byte {
	result := make([]byte, 1)
	result[0] = byte(b)
	return result
}

func decodeByte(buffer []byte) uint8 {
	return uint8(buffer[0])
}
