package decryption.ciphers;

import decryption.Constants.Algorithm;
import decryption.Constants.Mode;
import decryption.formats.FormatDefinition.Format;
import decryption.parameters.KeyParameters;

/**
 * The subclasses of Cipher allow the user to decrypt with knowledge of the algorithm and mode used during encryption.
 * They interact directly with the underlying ciphers from the Bouncy Castle APIs and take as input instances of {@link decryption.parameters} to hold the parameters
 * and instances of {@link decryption.formats.FormatDefinition.Format} to interface with encrypted data.
 * These classes are useful if the user knows the format of the encrypted data, but not the library that was used to generate it.
 * 
 * @author Francesco Rositano
 *
 */
public abstract class Cipher {
	protected Algorithm algorithm;
	protected Mode mode;
	protected KeyParameters parameters;
	
	protected Cipher(Algorithm algorithm, Mode mode, KeyParameters parameters) {
		this.algorithm = algorithm;
		this.mode = mode;
		this.parameters = parameters;
	}
	
	/**
	 * The main function of this class and the one which should be used.
	 * Decrypt a byte array of formatted encrypted data.
	 * 
	 * @param encryptedData data to be decrypted
	 * @param dataFormat format of encrypted data
	 * @return decrypted data or null if the decryption failed
	 */
	public abstract byte[] decrypt(byte[] encryptedData, Format dataFormat);
	
	public Algorithm getAlgorithm() {
		return algorithm;
	}
	
	public Mode getMode() {
		return mode;
	}
	
	public KeyParameters getParameters() {
		return parameters;
	}

}
