package decryption;

public class Constants {
	
	public interface Algorithm{
	}
	
	public enum BlockAlgorithm implements Algorithm {
		NONE(false),
		AES(true),
		CAMELLIA(true),
		DES(true),
		DES3(true),
		SERPENT(true),
		BLOWFISH(true),
		IDEA(true),
		TWOFISH(true);
		
		private boolean needsIv;
		
		private BlockAlgorithm(boolean needIv) {
			this.needsIv = needIv;
		}

		public boolean needsIv() {
			return needsIv;
		}
	};
	
	public enum StreamAlgorithm implements Algorithm {
		NONE(false),
		CHACHA20(true),
		RC4(false);
		
		private boolean needsIv;
		
		private StreamAlgorithm(boolean needIv) {
			this.needsIv = needIv;
		}

		public boolean needsIv() {
			return needsIv;
		}
	};
	
	public enum AEADAlgorithm implements Algorithm {
		NONE(false),
		AES_AEAD(true),
		CHACHA20POLY1305(false);
		
		private boolean isModeRequired;
		
		private AEADAlgorithm(boolean isModeRequired) {
			this.isModeRequired = isModeRequired;
		}
		
		public boolean requiresMode() {
			return isModeRequired;
		}
	};
	
	public interface Mode{
		
	}
	
	public enum EncryptionMode implements Mode { NONE, ECB, CBC, CTR, CFB, OFB };
	
	public enum AEADMode implements Mode { NONE, GCM, CCM, EAX};
	
	
	
}
