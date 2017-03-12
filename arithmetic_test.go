package protean

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The encoding input is a simple numerical sequence.
// The encoding output is taken from a reference implementation.
func TestEncodingShort(t *testing.T) {
	frequencies := sampleDecompressionConfig().Frequencies
	encoder := NewEncoder(frequencies)

	plain, _ := hex.DecodeString("00010203")
	target, _ := hex.DecodeString("CA0001020300000008")
	result := encoder.Encode(plain)
	if !bytes.Equal(result, target) {
		t.Fail()
	}
}

// The decoding input is taken from the output of the encoding test.
// The decoding output is taken from the input of the encoding test.
func TestDecodingShort(t *testing.T) {
	frequencies := sampleDecompressionConfig().Frequencies
	decoder := NewDecoder(frequencies)

	encoded, _ := hex.DecodeString("CA0001020300000008")
	target, _ := hex.DecodeString("00010203")
	result := decoder.Decode(encoded)

	if !bytes.Equal(result, target) {
		t.Fail()
	}
}

// The encoding input is an example of a real WebRTC packet.
// The encoding output is taken from a reference implementation.
func TestEncodingLong(t *testing.T) {
	frequencies := sampleDecompressionConfig().Frequencies
	encoder := NewEncoder(frequencies)

	plain, _ := hex.DecodeString("0001005C2112A442484E436A4E475466373145420006002134474A396549694D755955354338496A3A697A7251347772576670316B57664464000000802900089A85CD9550C8EE0A002400046E7E1EFF000800140345954222F0DA663E8EB8CC79A1F7BA010FD50080280004E2284303")
	target, _ := hex.DecodeString("CA0001005C2112A442484E436A4E475466373145420006002134474A396549694D755955354338496A3A697A7251347772576670316B57664464000000802900089A85CD9550C8EE0A002400046E7E1EFF000800140345954222F0DA663E8EB8CC79A1F7BA010FD50080280004E228430300000074")
	encoded := encoder.Encode(plain)

	if !bytes.Equal(encoded, target) {
		t.Fail()
	}
}

// The decoding input is taken from the output of the encoding test.
// The decoding output is taken from the input of the encoding test.
func TestDecodingLong(t *testing.T) {
	frequencies := sampleDecompressionConfig().Frequencies
	decoder := NewDecoder(frequencies)

	encoded, _ := hex.DecodeString("CA0001005C2112A442484E436A4E475466373145420006002134474A396549694D755955354338496A3A697A7251347772576670316B57664464000000802900089A85CD9550C8EE0A002400046E7E1EFF000800140345954222F0DA663E8EB8CC79A1F7BA010FD50080280004E228430300000074")
	target, _ := hex.DecodeString("0001005C2112A442484E436A4E475466373145420006002134474A396549694D755955354338496A3A697A7251347772576670316B57664464000000802900089A85CD9550C8EE0A002400046E7E1EFF000800140345954222F0DA663E8EB8CC79A1F7BA010FD50080280004E2284303")
	decoded := decoder.Decode(encoded)

	if !bytes.Equal(decoded, target) {
		t.Fail()
	}
}
