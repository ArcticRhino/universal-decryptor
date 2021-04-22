package decryption.ciphers;

import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import decryption.Constants.EncryptionMode;
import decryption.Constants.StreamAlgorithm;
import decryption.formats.DataFormatHelper;
import decryption.formats.FormatDefinition.EncryptionFormat;
import decryption.formats.FormatDefinition.Format;
import decryption.parameters.KeyIvCounterParameters;
import decryption.parameters.KeyIvParameters;
import decryption.parameters.KeyParameters;

/**
 * A {@link decryption.ciphers.Cipher} specialized in working with Stream algorithms.
 * It works with key and IV. In case of decryption with ChaCha, could take a counter as input.
 * 
 * @author Francesco Rositano
 *
 */
public class StreamCipher extends Cipher {
	
	/**
	 * most common and logical value for the ChaCha counter, to use if not working with a {@link decryption.formats.Library}
	 */
	public final int DEFAULT_COUNTER = 0;

	public StreamCipher(StreamAlgorithm algorithm, KeyParameters parameters) {
		super(algorithm, EncryptionMode.NONE, parameters);
	}

	@Override
	public byte[] decrypt(byte[] encryptedData, Format dataFormat) {
		EncryptionFormat encFormat = (EncryptionFormat)dataFormat;
		switch ((StreamAlgorithm)algorithm) {
		default:
			return null;
		case CHACHA20:
			return decryptChaCha20(encryptedData, encFormat);
		case RC4:
			return decryptRC4(encryptedData, encFormat);
		}
		
	}
	
	/**
	 * Used to decrypt with ChaCha, it get the right parameters, extracts the ciphertext
	 * and pass all this to {@link decryption.ciphers.StreamCipher#processStream(org.bouncycastle.crypto.StreamCipher, boolean, byte[], KeyParameter, byte[])}.
	 * It checks for a counter before using its default value of 0.
	 * <p>
	 * ChaCha accepts a nonce 12 bytes long (newer version to conform to ChaCha20-Poly1305) or 8 bytes long (legacy).
	 * The latter is converted to a 12 bytes nonce with leading zeroes
	 * 
	 * @param encryptedData the data to decrypt
	 * @param dataFormat the format of the encrypted data
	 * @return the decryption of encryptedData, or null if failed
	 */
	private byte[] decryptChaCha20(byte[] encryptedData, EncryptionFormat dataFormat) {
		KeyParameter keyParams = new KeyParameter(parameters.key);
		byte[] iv = null;
		int counter = DEFAULT_COUNTER;
		int ivSize = 0;
		// if the user supplied the counter, use it; the IV can, in this order of preference, be supplied by the user or extracted if possible
		if (parameters instanceof KeyIvCounterParameters) {
			KeyIvCounterParameters keyIvCounterParams = (KeyIvCounterParameters) parameters;
			iv = keyIvCounterParams.iv;
			if (keyIvCounterParams.iv != null) {
				iv = keyIvCounterParams.iv;
			} else {
				iv = DataFormatHelper.extractIvStandardEncryption(encryptedData, dataFormat, keyIvCounterParams.getIvLengthBytes());
			}
			if (iv == null) {
				return null;
			}
			counter = keyIvCounterParams.getCounterInt();
			ivSize = iv.length;
			// else if the user did not supply the counter, then its value is the default one.
			// The IV can, in this order of preference, be supplied by the user or extracted if possible
		}else if (parameters instanceof KeyIvParameters) {
			KeyIvParameters keyIvParams = (KeyIvParameters) parameters;
			iv = keyIvParams.iv;
			if (keyIvParams.iv != null) {
				iv = keyIvParams.iv;
			} else {
				iv = DataFormatHelper.extractIvStandardEncryption(encryptedData, dataFormat, keyIvParams.getIvLengthBytes());
			}
			if (iv == null) {
				return null;
			}
			ivSize = iv.length;
			counter = DEFAULT_COUNTER;
		} else{
			return null;
		}
		try {
			byte[] ciphertext = DataFormatHelper.extractCiphertextEncryption(encryptedData, dataFormat, ivSize);
			if(ciphertext == null) {
				return null;
			}
			if(ivSize == 12) {
				return decryptChacha20nonce96(ciphertext, parameters.key, iv, counter);
			} else if(ivSize == 8) {
				// the new 12 bytes nonce is four bytes of zeroes followed by the 8 bytes IV
				byte[] nonce96 = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
				System.arraycopy(iv, 0, nonce96, 4, 8);
				return decryptChacha20nonce96(ciphertext, parameters.key, nonce96, counter);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return null;
	}
	
	/**
	 * Decrypts with RC4; no IV is used
	 * 
	 * @param encryptedData the data to decrypt
	 * @param dataFormat the format of encryptedData
	 * @return the decryption of encryptedData, or null if failed
	 */
	private byte[] decryptRC4(byte[] encryptedData, EncryptionFormat dataFormat) {
		KeyIvParameters params = (KeyIvParameters)parameters;
		try {
			byte[] ciphertext = DataFormatHelper.extractCiphertextEncryption(encryptedData, dataFormat, params.getIvLengthBytes());
			if(ciphertext == null) {
				return null;
			}
			return processStream(new RC4Engine(), false, ciphertext, new KeyParameter(params.key), null);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Processes a ciphertext with a Bouncy Castle cipher.
	 * The input data of this function needs to consist of the result of encryption, without IV or other metadata,
	 * in order for Bouncy Castle to decrypt it properly.
	 * <p>
	 * Used only for decryption with RC4
	 * 
	 * @param streamCipher Bouncy Castle stream cipher to decrypt with
	 * @param encrypting true in case of encryption, false (default) in case of decryption
	 * @param input the ciphertext
	 * @param key Bouncy Castle wrapper for a key
	 * @param iv the IV to be used in decryption
	 * @return the decryption of input
	 * @throws Exception in case of wrong parameters or input size
	 */
	private byte[] processStream(org.bouncycastle.crypto.StreamCipher streamCipher, boolean encrypting, byte[] input, KeyParameter key, byte[] iv) throws Exception {
		CipherParameters params = null;
		if(iv == null) {
			params = key;
		} else {
			params = new ParametersWithIV(key, iv);
		}
		streamCipher.init(encrypting, params);
		byte output[] = new byte[input.length];
		streamCipher.processBytes(input, 0, input.length, output, 0);
		
		return output;
	}
	
	/**
	 * Processes a ciphertext with a JCE ChaCha20 cipher. This because Bouncy Castle does not support nonces of 12 bytes.
	 * The input data of this function needs to consist of the result of encryption, without IV or other metadata,
	 * in order for the JCE cipher to decrypt it properly.
	 * 
	 * @param cipherText the ciphertext to decrypt
	 * @param key the key used for decryption
	 * @param nonce96Bytes the 12 bytes long nonce
	 * @param counter the counter for ChaCha, usually 0
	 * @throws Exception in case of wrong parameters or input size
	 */
	private static byte[] decryptChacha20nonce96(byte[] cipherText, byte[] key, byte[] nonce96Bytes, int counter) throws Exception {
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("ChaCha20");
		ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce96Bytes, counter);
		SecretKeySpec keySpec = new SecretKeySpec(key, "ChaCha20");
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, paramSpec);
		byte[] decryptedText = cipher.doFinal(cipherText);
		return decryptedText;
	}

}
