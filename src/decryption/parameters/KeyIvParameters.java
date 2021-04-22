package decryption.parameters;

/**
 * This class wraps a key and an IV. In case the IV is unknown, its length in bytes can be specified.
 * 
 * @author Francesco Rositano
 *
 */
public class KeyIvParameters extends KeyParameters {
	public byte[] iv;
	protected int ivLengthBytes;
	
	public KeyIvParameters(byte[] key, byte[] iv) {
		super(key);
		this.iv = iv;
		if(iv != null) {
			ivLengthBytes = iv.length;
		}
	}
	
	public KeyIvParameters(byte[] key, int ivLengthBytes) {
		super(key);
		this.ivLengthBytes = ivLengthBytes;
		iv = null;
	}
	
	public int getIvLengthBytes() {
		return ivLengthBytes;
	}
	
	public int getIvLengthBits() {
		return ivLengthBytes * 8;
	}

}
