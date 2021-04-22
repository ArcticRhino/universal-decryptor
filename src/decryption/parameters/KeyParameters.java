package decryption.parameters;

/**
 * This class is the base for every other "XXXParameters" class.
 * It only wraps a key; as such, it is only useful in the case of RC4
 * because it does not need an IV to properly decrypt
 * 
 * @author Francesco Rositano
 *
 */
public class KeyParameters {
	public byte[] key;
	protected int keyLengthBytes;
	
	public KeyParameters(byte[] key) {
		this.key = key;
		if(key != null) {
			keyLengthBytes = key.length;
		} else {
			keyLengthBytes = 0;
		}
	}
	
	public int getKeyLengthBytes() {
		return keyLengthBytes;
	}
	
	public int getKeyLengthBits() {
		return keyLengthBytes * 8;
	}
}
