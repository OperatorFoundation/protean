package protean

import (
	"errors"
)

// Here is some background reading on arithmetic coding and range coding.
// http://www.arturocampos.com/ac_arithmetic.html
// http://www.arturocampos.com/ac_range.html
// http://www.compressconsult.com/rangecoder/
// http://sachingarg.com/compression/entropy_coding/range_coder.pdf
// http://ezcodesample.com/reanatomy.html
// http://www.cc.gatech.edu/~jarek/courses/7491/Arithmetic2.pdf
// http://www.drdobbs.com/cpp/data-compression-with-arithmetic-encodin/240169251?pgno=2

// Summarized from "A Fast Renormalisation Method for Arithmetic Coding" by
// Michael Schindler:
//
// At any point during arithmetic coding the output consists of four parts:
// 1. The part already written into the output buffer and does not change.
// 2. One digit that may be changed by at most one carry when adding to the
//    lower end of the interval. There will never be two carries. since the
//    range when fixing that digit was <= 1 unit. Two carries would require
//    range > 1 unit.
// 3. There is a (possibly empty) block of digits that pass on a carry. (255 for
//    bytes) that are represented by a counter counting their number.
// 4. The last part is represented by the low end range variable of the encoder.

// Returns the sum of a list of numbers
func sum(items []uint32) uint32 {
	var accum uint32
	for _, item := range items {
		accum = accum + item
	}

	return accum
}

// Takes an input list of integer and returns a list of integers where all of
// the input integer have been divided by a constant.
func scale(items []uint32, divisor uint32) []uint32 {
	var results []uint32 = make([]uint32, len(items))
	for index, item := range items {
		scaled := item / divisor
		if scaled == 0 {
			results[index] = 1
		} else {
			results[index] = scaled
		}
	}

	return results
}

// Takes a list of numbers where the inputs should all be integers from 0 to
// 255 and converts them to bytes in an []byte.
func SaveProbs(items []uint32) ([]byte, error) {
	bs := make([]byte, len(items))
	for index, item := range items {
		if item >= 0 && item <= 255 {
			bs[index] = byte(item)
		} else {
			return nil, errors.New("Probabilities must be between 0 and 255 inclusive.")
		}
	}

	return bs, nil
}

// Models a symbol as an interval in the arithmetic coding space
type Interval struct {
	// The byte that corresponds to this interval in the coding
	symbol uint8

	// The lower range of the interval
	low uint32

	// The length of this interval
	length uint32

	// The upper range of this interval
	// This should always be lower+length
	// This is precomputed and stored separately in order to increase the clarity
	// of the implementation of the coding algorithm.
	high uint32
}

// Creates a new interval
// This maintains the constraint that high = low + length.
func makeInterval(symbol uint8, low uint32, length uint32) Interval {
	return Interval{symbol: symbol, low: low, length: length, high: low + length}
}

// The precision of the arithmetic coder
const CODE_BITS uint32 = 32

// The maximum possible signed value given the precision of the coder.
// 2^(32-1)
const TOP_VALUE uint32 = 2147483648

// The maximum possible unsigned value given the precision of the coder.
// (2^32)-1
const MAX_INT uint32 = 4294967295

// The number of bits to shift over during renormalization.
const SHIFT_BITS uint32 = CODE_BITS - 9

// Tne number of bits left over during renormalization.
const EXTRA_BITS uint32 = (CODE_BITS-2)%8 + 1

// The lowest possible value.
// Anything lower than this will be shifted up during renormalization.
const BOTTOM_VALUE uint32 = TOP_VALUE >> 8

// The state and initialiation code for arithmetic coding.
// This class is never instantiated directly.
// The subclasses Encoder and Decoder are used instead.
type Coder struct {
	// The probability distribution of the input.
	// This will be a list of 256 entries, each consisting of an integer from
	// 0 to 255.
	probabilities []uint32

	// The low end of the encoded range. Starts at 0.
	low uint32

	// The high end of the encoded range. Starts at the maximum 32-bit value.
	high uint32

	// The extra bits that need to be stored for later if underflow occurs.
	underflow uint32

	// The current byte that's being constructed for eventual output.
	working uint32

	// A coding table derived from the probability distribution.
	intervals map[uint8]Interval

	// The total of the lengths of all intervals in the coding table.
	// This determines the maximum amount that the range can change by encoding
	// one symbol.
	total uint32

	// The input buffer. This is a list of bytes represented as numbers.
	input []uint32

	// The output buffer. This is a list of bytes represented as numbers.
	output []uint32
}

// The Coder constructor normalizes the symbol probabilities and build the
// coding table.
func NewCoder(probs []uint32) Coder {
	this := Coder{}

	// Scale the symbol probabilities to fit constraints.
	this.probabilities = adjustProbs(probs)
	this.low = 0x00000000
	this.high = 0xFFFFFFFF
	this.intervals = make(map[uint8]Interval)

	// Build the symbol table.
	var low uint32
	for index, prob := range probs {
		this.intervals[uint8(index)] = makeInterval(uint8(index), low, prob)
		low = low + prob
	}

	// Calculate the sum of the lengths of all intervals.
	this.total = sum(this.probabilities)

	return this
}

func max(items []uint32) uint32 {
	var top uint32
	for _, item := range items {
		if item > top {
			top = item
		}
	}

	return top
}

// Scale the symbol probabilities to fit the following constraints:
// - No probability can be higher than 255.
// - The sum of all probabilities must be less than 2^14.
func adjustProbs(probs []uint32) []uint32 {
	// The maximum value for any single probability
	const MAX_PROB uint32 = 255

	// The amount to scale probabilities if they are greater than the maximum.
	const SCALER uint32 = 256

	// The maximum value for the sum of all probabilities. 2^14
	const MAX_SUM uint32 = 16384

	// If any single probability is too high, rescale.
	var highestProb = max(probs)
	if highestProb > MAX_PROB {
		divisor := highestProb / SCALER
		probs = scale(probs, divisor)
	}

	// If the sum of probabilities is too high, rescale.
	for sum(probs) >= MAX_SUM {
		probs = scale(probs, 2)
	}

	return probs
}

// Encodes a sequence of bytes using a probability distribution with the goal of
// yielding a higher entropy sequence of bytes.
type Encoder struct {
	// extends Coder
	Coder
}

func NewEncoder(probs []uint32) Encoder {
	return Encoder{Coder: NewCoder(probs)}
}

func NewDecoder(probs []uint32) Decoder {
	return Decoder{Coder: NewCoder(probs)}
}

// Encode a sequence of bytes.
func (this *Encoder) Encode(input []byte) []byte {
	// Initialize state.
	// The Coder superclass initializes state common to Encoder and Decoder.
	// Encoder and Decoder do some additional initialization that must be
	// reset when encoding each byte sequence.
	this.init()

	// Encode all of the symbols in the input []byte
	// The primary effect is to fill up the output buffer with output bytes.
	// Internal state variables also change after encoding each symbol.
	for _, b := range input {
		this.encodeSymbol(b)
	}

	// Flush any remaining state in the internal state variables into
	// the output buffer.
	this.flush()

	// Copy the output buffer into an []byte that can be returned.
	var output = make([]byte, len(this.output))
	for index, item := range this.output {
		output[index] = byte(item)
	}

	// Return the []byte copy of the internal output buffer.
	return output
}

// Initialize state.
// The Coder superclass initializes state common to Encoer and Decoder.
// Encoder and Decoder do some additional initialization that must be
// reset when encoding each byte sequence.
func (this *Encoder) init() {
	this.low = 0
	this.high = TOP_VALUE
	this.working = 0xCA
	this.underflow = 0
	this.input = []uint32{}
	this.output = []uint32{}
}

// Encode a symbol. The symbol is a byte represented as a number.
// The effect of this is to change internal state variables.
// As a consequence, bytes may of may not be written to the output buffer.
// When all symbols have been encoded, flush() must be called to recover any
// remaining state.
func (this *Encoder) encodeSymbol(symbol uint8) {
	// Look up the corresponding interval for the symbol in the coding table.
	// This is what we actually use for encoding.
	interval := this.intervals[symbol]

	// Renormalize. This is the complicated but less interesting part of coding.
	// This is also where bytes are actually written to the output buffer.
	this.renormalize()

	// Now do the interesting part of arithmetic coding.
	// Every sequence of symbols is mapped to a positive integer.
	// As we encode each symbol we are calculating the digits of this integer
	// using the interval information for the symbol.
	// The result of encoding a symbol is a new range, as represented by are new
	// values for low and high.

	// The new symbol subdivides the existing range.
	// Take the existing range and subdivide it by the total length of the
	// intervals in the coding table.
	newRange := this.high / this.total

	// Find the place in the new subdivide range where the new symbol's interval
	// begins.
	temp := newRange * interval.low

	// The case where the symbol being encoded has the highest range is a
	// special case.
	if interval.high >= this.total {
		// Special case where the symbol being encoded has the highest range
		// Adjust the high part of the range
		this.high = this.high - temp
	} else {
		// General case
		// Adjust the high part of the range
		this.high = newRange * interval.length
	}

	// Adjust the low part of the range
	this.low = this.low + temp
}

// Summarized from "A Fast Renormalisation Method for Arithmetic Coding" by
// Michael Schindler:
//
// When doing encoding renormalisation the following can happen:
// A No renormalisation is needed since the range is in the desired interval.
// B The low end plus the range (this is the upper end of the interval) will
//   not produce any carry. In this case the second and third part can be
//   output as they will never change. The digit produced will become part two
//   and part three will be empty.
// C The low end has already produced a carry. Here the (changed) second and
//   third part can be output. There will not be another carry. Set the second
//   and third part as before.
// D The digit produced will pass on a possible future carry, so it is added
//   to the third block.
func (this *Encoder) renormalize() {
	// If renormalization is needed, we are in case B, C, or D.
	// Otherwise, we are in case A.
	for this.high <= BOTTOM_VALUE {
		if this.low < (0xFF << SHIFT_BITS) {
			// B The low end plus the range (this is the upper end of the interval) will
			//   not produce any carry. In this case the second and third part can be
			//   output as they will never change. The digit produced will become part two
			//   and part three will be empty.
			this.write(this.working)
			for this.underflow != 0 {
				this.underflow = this.underflow - 1
				this.write(0xFF)
			}
			this.working = (this.low >> SHIFT_BITS) & 0xFF
		} else if (this.low & TOP_VALUE) != 0 {
			// C The low end has already produced a carry. Here the (changed) second and
			//   third part can be output. There will not be another carry. Set the second
			//   and third part as before.
			this.write(this.working + 1)
			for this.underflow != 0 {
				this.underflow = this.underflow - 1
				this.write(0x00)
			}

			this.working = (this.low >> SHIFT_BITS) & 0xFF
		} else {
			// D The digit produced will pass on a possible future carry, so it is added
			//   to the third block.
			this.underflow = this.underflow + 1
		}

		// This is the goal of renormalization, to move the whole range over 8
		// bits in order to make room for more computation.
		this.high = (this.high << 8) >> 0
		this.low = ((this.low << 8) & (TOP_VALUE - 1)) >> 0
	}

	// A No renormalisation is needed since the range is in the desired interval.
}

func (this *Encoder) flush() {
	// Output the internal state variables.
	this.renormalize()
	var temp = this.low >> SHIFT_BITS
	if temp > 0xFF {
		this.write(this.working + 1)
		for this.underflow != 0 {
			this.underflow = this.underflow - 1
			this.write(0x00)
		}
	} else {
		this.write(this.working)
		for this.underflow != 0 {
			this.underflow = this.underflow - 1
			this.write(0xFF)
		}
	}

	// Output the remaining internal state.
	this.write(temp & 0xFF)
	this.write((this.low >> (23 - 8)) & 0xFF)

	// Output the length
	this.write((uint32(len(this.output)) >> uint32(8)) & uint32(0xFF))
	this.write(uint32(len(this.output)) & uint32(0xFF))
}

func (this *Encoder) write(b uint32) {
	this.output = append(this.output, b)
}

// Decodes a sequence of bytes using a probability distribution with the goal of
// yielding a lower entropy sequence of bytes.
type Decoder struct {
	//extends Coder
	Coder
}

// Decode a sequence of bytes
func (this *Decoder) Decode(input []byte) []byte {
	// Create an empty input buffer.
	this.input = []uint32{}

	// Fetch the size of the target output.
	// This is encoded as two bytes at the end of the encoded byte sequence.
	var sizeBytes = input[len(input)-2:]
	// Decode the two-byte size into a number.
	var size = decodeShort(sizeBytes) - 4

	// Copy the bytes from the given []byte into the internal input buffer.
	for index := uint16(0); index < size; index++ {
		this.input = append(this.input, uint32(input[index]))
	}

	// Initialize state.
	// The Coder superclass initializes state common to Encoder and Decoder.
	// Encoder and Decoder do some additional initialization that must be
	// reset when encoding each byte sequence.
	this.init()
	// Decode all of the symbols in the input buffer
	// The primary effect is to fill up the output buffer with output bytes.
	// Internal state variables also change after decoding each symbol.
	this.decodeSymbols()
	// Flush any remaining state in the internal state variables into
	// the output buffer.
	this.flush()

	// Copy the output buffer into an []byte that can be returned.
	output := make([]byte, len(this.output))
	for index, item := range this.output {
		output[index] = byte(item)
	}

	return output
}

// Initialize state variables for decoding.
func (this *Decoder) init() {
	// Discard first byte because the encoder is weird.
	this.input = this.input[1:]

	this.working = this.input[0]
	this.input = this.input[1:]
	this.low = this.working >> (8 - EXTRA_BITS)
	this.high = 1 << EXTRA_BITS
	this.underflow = 0
	this.output = []uint32{}
}

// Decode symbols from the input buffer until it is empty.
func (this *Decoder) decodeSymbols() {
	for len(this.input) > 0 {
		this.decodeSymbol()
	}
}

// Run the decoding algorithm. This uses internal state variables and
// may or may not consume bytes from the input buffer.
// The primary result of running this is changing internal state variables
// and one byte will always be written to the output buffer.
// After decoding symbols, flush must be called to get the remaining state
// out of the internal state variables.
func (this *Decoder) decodeSymbol() {
	// Renormalize. This is the complicated but less interesting part of coding.
	// This is also where bytes are actually read from the input buffer.
	this.renormalize()

	//
	this.underflow = this.high >> 8
	temp := (this.low / this.underflow) >> 0

	// Calculate the byte to output.
	// There is a special case for 255.
	var result uint32
	if temp>>8 != 0 {
		// Special case.
		// Output 255.
		result = 255
	} else {
		// General case.
		// Output the byte that has been calculated.
		result = temp
	}

	// Output the decoded byte into the output buffer.
	this.output = append(this.output, result)

	// Update the internal state variables base on the byte that was decoded.
	this.update(result)
}

// Renormalizing is the tricky but boring part of coding.
// The purpose of renormalizing is to allow the computation of an arbitrary
// precision fraction using only 32 bits of space.
// In the range coding variant of arithmetic coding implemented here,
// renormalization happens at bytes instead of bits. This means that it
// happens less frequently and so is faster to compute.
func (this *Decoder) renormalize() {
	// Renormalization clears bits out of the working area to make room for
	// more bits for computation. Continue until the working area is clear.
	for this.high <= BOTTOM_VALUE {
		// More the high bits over to make room.
		// This might have caused the sign bit to be set, so coerce from a float
		// to a 32-bit unsigned int.
		this.high = (this.high << 8) >> 0

		// Shift the low end of the range over to make room.
		// Shift the working byte and move it into the low end of the range.
		this.low = (this.low << 8) | ((this.working << EXTRA_BITS) & 0xFF)

		// Obtain new bits to decode if there are any in the input buffer.
		// There is a special case when the input buffer is empty.
		if len(this.input) == 0 {
			// Special case. The input buffer is empty.
			// This will only be called for flushing the internal state variables.
			this.working = 0
		} else {
			// General case. There input buffer has bits that have not been decoded.
			// Put them in the working byte.
			this.working = this.input[0]
			this.input = this.input[1:]
		}

		// Load the bits from the new working byte into the low end of the range.
		// Be careful not to overwrite the bits we stored in there from the old
		// working byte.
		this.low = (this.low | (this.working >> (8 - EXTRA_BITS)))
		// Coerce the low end of the range from a float to a 32-bit unsigned int.
		this.low = this.low >> 0
	}
}

// Update internal state variables based on the symbol that was last decoded.
func (this *Decoder) update(symbol uint32) {
	// Look up the corresponding interval for the symbol in the coding table.
	// This is what we actually use for encoding.
	interval := this.intervals[uint8(symbol)]

	// Recover the bits stored from the underflow
	// This will be 0 if there are no underflow bits.
	temp := this.underflow * interval.low

	// Adjust the low value to account for underflow.
	// There is no adjustment if there are no underflow bits.
	this.low = this.low - temp

	// The case where the symbol being encoded has the highest range is a
	// special case.
	if interval.high >= this.total {
		// Special case where the symbol being encoded has the highest range
		// Adjust the high part of the range
		this.high = this.high - temp
	} else {
		// General case
		// Adjust the high part of the range
		this.high = this.underflow * interval.length
	}
}

// Get the remaining information from the internal state variables and
// write it to the output buffer.
// This should be called after the input buffer is empty.
func (this *Decoder) flush() {
	// Attempt to decode a symbol even though the input buffer is empty.
	// This should get the remaining state out of working.
	this.decodeSymbol()
	// Renormalize. This should get the remaining state out of the rest of the
	// internal state variables.
	this.renormalize()
}
