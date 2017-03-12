package protean

type Transformer interface {
	/**
	 * Sets the key for this Transformer session.
	 *
	 * @param {[]byte} key session key.
	 * @return {boolean} true if successful.
	 */
	SetKey(key []byte)

	/**
	 * Configures this Transformer.
	 *
	 * @param {String} serialized Json string.
	 */
	Configure(json string)

	/**
	 * Transforms a piece of data to obfuscated form.
	 *
	 * @param {[]byte} plaintext data that needs to be obfuscated.
	 * @return {[]byte[]} list of []bytes of obfuscated data.
	 * The list can contain zero, one, or more than one items.
	 * In the case of fragmentation:
	 *   When fragmention occurs, the list will have more than one item.
	 *   When there is no fragmentation, the list will have one item.
	 */
	Transform(buffer []byte) [][]byte

	/**
	 * Restores data from obfuscated form to original form.
	 *
	 * @param {[]byte} ciphertext obfuscated data.
	 * @return {[]byte} list of []bytes of original data.
	 * The list can contain zero, one, or more than one items.
	 * In the case of fragmentation:
	 *   When receiving a fragment, the list will have zero items,
	 *   unless it was the last fragment, then the list will have one item.
	 */
	Restore(buffer []byte) [][]byte

	/**
	 * Dispose the Transformer.
	 *
	 * This should be the last method called on a Transformer instance.
	 */
	Dispose()
}
