package decryption;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import decryption.Constants.BlockAlgorithm;
import decryption.Constants.EncryptionMode;
import decryption.ciphers.BlockCipher;
import decryption.formats.DataFormatHelper;
import decryption.formats.FormatDefinition.EncryptionFormat;
import decryption.parameters.KeyIvParameters;

/**
 * Decryptor specialized in dealing with Defuse, a PHP encryption library.
 * Defuse uses AES256 CTR to encrypt; from a key k, supplied by the user,
 * a pair of keys is generated using SHA256 on k.
 * If the user wants to encrypt with a password, k is generated applying SHA256 on the password.
 * 
 * @author Francesco Rositano
 *
 */
public class DefuseDecryptor {
	/**
	 * constant of the encryption key derivation process of Defuse
	 */
	private static final byte[] encryptionKeyGenerationInfo = "DefusePHP|V2|KeyForEncryption".getBytes();
	private static final int encryptionKeyLengthBytes = 32;
	/**
	 * the number of rounds the password-based key-derivation function is applied
	 */
	private static final int PBKDF_ITERATION_COUNT = 100000;
	
	/**
	 * Decrypts with a key.
	 * 
	 * @param encryptedData data to decrypt
	 * @param key the key used in encryption
	 * @return decryption of encryptedData, or null if failed
	 */
	public static byte[] decrypt(byte[] encryptedData, byte[] key) {
		byte[] salt = DataFormatHelper.extractSaltDefuse(encryptedData);
		byte[] iv = DataFormatHelper.extractIvDefuse(encryptedData);
		byte[] ciphertext = DataFormatHelper.extractCiphertextDefuse(encryptedData);
		if(salt == null || iv == null || ciphertext == null) {
			return null;
		}
		byte[] realEncryptionKey = generateEncryptionKey(key, salt);
		if(realEncryptionKey == null) {
			return null;
		}
		return decryptWithParameters(ciphertext, realEncryptionKey, iv);
	}
	
	/**
	 * Decrypts using a password.
	 * 
	 * @param encryptedData data to decrypt
	 * @param password the password used in encryption
	 * @return decryption of encryptedData, or null if failed
	 */
	public static byte[] decrypt(byte[] encryptedData, String password) {
		byte[] salt = DataFormatHelper.extractSaltDefuse(encryptedData);
		if(salt == null) {
			return null;
		}
		byte[] key = generateKeyFromPassword(password, salt);
		byte[] iv = DataFormatHelper.extractIvDefuse(encryptedData);
		byte[] ciphertext = DataFormatHelper.extractCiphertextDefuse(encryptedData);
		if(key == null || iv == null || ciphertext == null) {
			return null;
		}
		byte[] realEncryptionKey = generateEncryptionKey(key, salt);
		if(realEncryptionKey == null) {
			return null;
		}
		return decryptWithParameters(ciphertext, realEncryptionKey, iv);
	}
	
	/**
	 * Generate a master key from a password, using SHA256.
	 * 
	 * @param password the password supplied in encryption
	 * @param salt the salt used together with the password; it is recovered from the ciphertext
	 * @return the master key
	 */
	private static byte[] generateKeyFromPassword(String password, byte[] salt) {
		// first, the password is hashed with SHA256
		byte[] hashedPassword = new byte[encryptionKeyLengthBytes];
		SHA256Digest passwordDigest = new SHA256Digest();
		passwordDigest.update(password.getBytes(), 0, password.getBytes().length);
		passwordDigest.doFinal(hashedPassword, 0);

		// password-based key derivation function defined in RFC 2898, applied to the hashed password
		PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
		generator.init(hashedPassword, salt, PBKDF_ITERATION_COUNT);
		KeyParameter keyParam = (KeyParameter) generator.generateDerivedParameters(encryptionKeyLengthBytes * 8);
		return keyParam.getKey();
	}

	/**
	 * Generates an encryption key applying SHA256 on the master key.
	 * Uses the constant {@link decryption.DefuseDecryptor#encryptionKeyGenerationInfo}.
	 * 
	 * @param key the master key, user supplied or derived from the password using {@link decryption.DefuseDecryptor#generateKeyFromPassword(String, byte[])}
	 * @param salt the salt used to generate the encryption key
	 * @return an encryption key suitable for decryption with AES CTR
	 */
	private static byte[] generateEncryptionKey(byte[] key, byte[] salt) {
		HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
		HKDFParameters params = new HKDFParameters(key, salt, encryptionKeyGenerationInfo);
		generator.init(params);
		byte[] generatedKey = new byte[encryptionKeyLengthBytes];
		generator.generateBytes(generatedKey, 0, encryptionKeyLengthBytes);
		return generatedKey;
	}
	
	/**
	 * Uses a {@link decryption.ciphers.BlockCipher} to decrypt the extracted ciphertext.
	 * 
	 * @param vanillaCiphertext the extracted ciphertext
	 * @param realKey the encryption key
	 * @param iv the extracted IV
	 * @return the decryption of vanillaCiphertext
	 */
	private static byte[] decryptWithParameters(byte[] vanillaCiphertext, byte[] realKey, byte[] iv) {
		KeyIvParameters params = new KeyIvParameters(realKey, iv);
		BlockCipher aesCTRCipher = new BlockCipher(BlockAlgorithm.AES, EncryptionMode.CTR, params);
		return aesCTRCipher.decrypt(vanillaCiphertext, EncryptionFormat.VANILLA);
	}
}
