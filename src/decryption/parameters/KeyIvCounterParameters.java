package decryption.parameters;

import utilities.IntBytesConverter;

/**
 * This class wraps a key, an IV and a counter and it is mostly used to decrypt with ChaCha and any block algorithm with CTR mode.
 * <p>
 * The counter can be specified as an integer or as an array of bytes:
 * the two methods {@link decryption.parameters.KeyIvCounterParameters#getCounterInt()} and {@link decryption.parameters.KeyIvCounterParameters#getCounterBytes()}
 * are used to get the counter value in the desired format.
 * 
 * @author Francesco Rositano
 *
 */
public class KeyIvCounterParameters extends KeyIvParameters {
	public int counterValue;
	public byte[] counterBytes;
	
	public KeyIvCounterParameters(byte[] key, byte[] iv, int counter) {
		super(key, iv);
		this.counterValue = counter;
		counterBytes = null;
	}
	
	public KeyIvCounterParameters(byte[] key, byte[] iv, byte[] counter) {
		super(key, iv);
		this.counterBytes = counter;
		counterValue = -1;
	}

	/**
	 * It is used to get the counter value as an integer.
	 * 
	 * @param isBigEndian specify if counterBytes has to be considered big-endian. Default value is false
	 * @return counterValue, if specified, or the conversion of counterBytes as an integer
	 */
	public int getCounterInt(boolean isBigEndian) {
		if(counterValue >= 0) {
			return counterValue;
		} else if(counterBytes != null) {
			return IntBytesConverter.bytesToInt(counterBytes, isBigEndian);
		} else {
			return -1;
		}
	}
	
	public int getCounterInt() {
		return getCounterInt(false);
	}
	
	/**
	 * It is used to get the counter value as an array of bytes.
	 * 
	 * @return counterBytes, if specified, or the conversion of counterValue as an array of bytes
	 */
	public byte[] getCounterBytes() {
		if(counterBytes != null) {
			return counterBytes;
		} else if(counterValue >= 0){
			return IntBytesConverter.intToBytes(counterValue);
		} else {
			return null;
		}
	}
}
