package decryption.parameters;

/**
 * This class wraps a key, an IV and a tag, used in the case of Authenticated Encryption.
 * If the tag is unknown, its length in bytes can be specified.
 * 
 * @author Francesco Rositano
 *
 */
public class KeyAEADParameters extends KeyIvParameters {
	public static final int UNKNOWN = -1;
	public static final int DEFAULT_TAG_LENGTH_BYTES = 16;

	public byte[] tag;
	protected int tagLengthBytes;
	
	public KeyAEADParameters(byte[] key, byte[] iv, int tagLengthBytes) {
		super(key, iv);
		this.tagLengthBytes = tagLengthBytes;
		this.tag = null;
	}
	
	public KeyAEADParameters(byte[] key, byte[] iv, byte[] tag) {
		super(key, iv);
		this.tag = tag;
		if(tag != null) {
			this.tagLengthBytes = tag.length;
		}
	}
	
	public KeyAEADParameters(byte[] key, byte[] iv) {
		super(key, iv);
		this.tagLengthBytes = DEFAULT_TAG_LENGTH_BYTES;
		this.tag = null;
	}
	
	public int getTagSizeBytes() {
		return tagLengthBytes;
	}
	
	public int getTagSizeBits() {
		return tagLengthBytes * 8;
	}
}
