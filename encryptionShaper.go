package protean

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const CHUNK_SIZE = 16
const IV_SIZE = 16

// Accepted in serialised form by Configure().
type EncryptionConfig struct {
	Key string
}

// Creates a sample (non-random) config, suitable for testing.
func sampleEncryptionConfig() EncryptionConfig {
	var bytes = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	hexHeader := hex.EncodeToString(bytes)
	return EncryptionConfig{Key: hexHeader}
}

// A packet shaper that encrypts the packets with AES CBC.
type EncryptionShaper struct {
	key []byte
}

func NewEncryptionShaper() *EncryptionShaper {
	shaper := &EncryptionShaper{}
	config := sampleEncryptionConfig()
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return nil
	}

	shaper.Configure(string(jsonConfig))
	return shaper
}

// This method is required to implement the Transformer API.
// @param {[]byte} key Key to set, not used by this class.
func (shaper *EncryptionShaper) SetKey(key []byte) {
}

// Configure the Transformer with the headers to inject and the headers
// to remove.
func (shaper *EncryptionShaper) Configure(jsonConfig string) {
	var config EncryptionConfig
	err := json.Unmarshal([]byte(jsonConfig), &config)
	if err != nil {
		fmt.Println("Encryption shaper requires key parameter")
	}

	shaper.ConfigureStruct(config)
}

func (shaper *EncryptionShaper) ConfigureStruct(config EncryptionConfig) {
	shaper.key = deserializeEncryptionConfig(config)
}

// Decode the key from string in the config information
func deserializeEncryptionConfig(config EncryptionConfig) []byte {
	return deserializeEncryptionModel(config.Key)
}

// Decode the header from a string in the header model
func deserializeEncryptionModel(model string) []byte {
	config, _ := hex.DecodeString(model)
	return config
}

// Inject header.
func (shaper *EncryptionShaper) Transform(buffer []byte) [][]byte {
	// This Transform performs the following steps:
	// - Generate a new random CHUNK_SIZE-byte IV for every packet
	// - Encrypt the packet contents with the random IV and symmetric key
	// - Concatenate the IV and encrypted packet contents
	var iv []byte = makeIV()
	var encrypted []byte = encrypt(shaper.key, iv, buffer)
	return [][]byte{append(iv, encrypted...)}
}

func (shaper *EncryptionShaper) Restore(buffer []byte) [][]byte {
	// This Restore performs the following steps:
	// - Split the first CHUNK_SIZE bytes from the rest of the packet
	//     The two parts are the IV and the encrypted packet contents
	// - Decrypt the encrypted packet contents with the IV and symmetric key
	// - Return the decrypted packet contents
	var iv = buffer[0:IV_SIZE]
	var ciphertext = buffer[IV_SIZE:]
	return [][]byte{decrypt(shaper.key, iv, ciphertext)}
}

// No-op (we have no state or any resources to Dispose).
func (shaper *EncryptionShaper) Dispose() {
}

func makeIV() []byte {
	var randomBytes = make([]byte, IV_SIZE)
	rand.Read(randomBytes)
	return randomBytes
}

func encrypt(key []byte, iv []byte, buffer []byte) []byte {
	var length []byte = encodeShort(uint16(len(buffer)))
	var remainder = (len(length) + len(buffer)) % CHUNK_SIZE
	var plaintext []byte
	if remainder == 0 {
		plaintext = append(length, buffer...)
	} else {
		var padding = make([]byte, CHUNK_SIZE-remainder)
		rand.Read(padding)
		plaintext = append(length, buffer...)
		plaintext = append(plaintext, padding...)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	var enc = cipher.NewCBCEncrypter(block, iv)

	var ciphertext []byte

	for x := 0; x < (len(plaintext) / CHUNK_SIZE); x++ {
		plainChunk := plaintext[x*CHUNK_SIZE : (x+1)*CHUNK_SIZE]
		cipherChunk := make([]byte, len(plainChunk))
		enc.CryptBlocks(cipherChunk, plainChunk)
		ciphertext = append(ciphertext, cipherChunk...)
	}

	return ciphertext
}

func encodeShort(value uint16) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())

	return buf.Bytes()
}

func decodeShort(b []byte) uint16 {
	var value uint16
	reader := bytes.NewReader(b)
	err := binary.Read(reader, binary.LittleEndian, &value)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}

	return value
}

func decrypt(key []byte, iv []byte, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	var dec = cipher.NewCBCDecrypter(block, iv)

	var plaintext []byte

	for x := 0; x < (len(ciphertext) / CHUNK_SIZE); x++ {
		cipherChunk := ciphertext[x*CHUNK_SIZE : (x+1)*CHUNK_SIZE]
		plainChunk := make([]byte, len(cipherChunk))
		dec.CryptBlocks(plainChunk, cipherChunk)
		plaintext = append(plaintext, plainChunk...)
	}

	lengthBytes := plaintext[0:2]
	length := decodeShort(lengthBytes)
	rest := plaintext[2:]

	if len(rest) > int(length) {
		return rest[0:length]
	} else {
		return rest
	}
}
