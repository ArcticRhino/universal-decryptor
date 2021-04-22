package decryption.formats;

/**
 * Collection of decryption/file format definitions supported by this library.
 * 
 * @author Francesco Rositano
 *
 */
public class FormatDefinition {

	public interface Format {
		
	}
	
	/**
	 * Enumeration of the supported decryption formats that result from a Standard Encryption (Block/Stream algorithms).
	 * Some formats include the IV used in encryption: in these cases, decryption may work even if an IV is not supplied by the user; it will be recovered.
	 *
	 */
	public enum EncryptionFormat implements Format {
		NONE(false),
		VANILLA(false),
		ADDED_PADDING(false),
		CIPHERTEXT_IV(true),
		IV_CIPHERTEXT(true),
		OPENSSL(false),
		GNUPG(false),
		DEFUSE_PHP(true);
		
		private boolean hasIv;
		
		private EncryptionFormat(boolean hasIv) {
			this.hasIv = hasIv;
		}
		
		public boolean containsIv() {
			return hasIv;
		}
	};
	
	/**
	 * Enumeration of the supported decryption formats that result from an Authenticated Encryption with Associated Data (AEAD algorithms).
	 * Some formats include the IV used in encryption: in these cases, decryption may work even if an IV is not supplied by the user; it will be recovered.
	 * Some formats include the tag generated in encryption. Even though the tag is not mandatory for decryption, it is important to be aware
	 * of its presence in order to remove it from the ciphertext
	 */
	public enum AEADFormat implements Format {
		NONE(false, false),
		SEPARATED(false, false),
		TAG_CIPHERTEXT(false, true),
		CIPHERTEXT_TAG(false, true),
		IV_CIPHERTEXT_TAG(true, true),
		OPENSSL(false, false),
		GNUPG(false, false);
		
		private boolean hasIv;
		private boolean hasTag;

		private AEADFormat(boolean hasIv, boolean hasTag) {
			this.hasIv = hasIv;
			this.hasTag = hasTag;
		}
		
		public boolean containsIv() {
			return hasIv;
		}

		boolean containsTag() {
			return hasTag;
		}
	};

}
