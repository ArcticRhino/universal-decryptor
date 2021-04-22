package decryption.ciphers;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.IDEAEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import decryption.formats.FormatDefinition.EncryptionFormat;
import decryption.formats.FormatDefinition.Format;
import decryption.Constants.BlockAlgorithm;
import decryption.Constants.EncryptionMode;
import decryption.formats.DataFormatHelper;
import decryption.parameters.KeyIvParameters;

/**
 * A {@link decryption.ciphers.Cipher} specialized in working with Block algorithms.
 * It works with key and IV.
 * 
 * @author Francesco Rositano
 *
 */
public class BlockCipher extends Cipher {

	public BlockCipher(BlockAlgorithm algorithm, EncryptionMode mode, KeyIvParameters parameters) {
		super(algorithm, mode, parameters);
	}

	
	@Override
	public byte[] decrypt(byte[] encryptedData, Format dataFormat) {
		KeyIvParameters keyIvParameters = (KeyIvParameters) parameters;
		EncryptionFormat encFormat = (EncryptionFormat)dataFormat;
		switch ((EncryptionMode)mode) {
			case CBC:
				return decryptCBC(encryptedData, encFormat, keyIvParameters);
			case CTR:
				return decryptCTR(encryptedData, encFormat, keyIvParameters);
			case NONE:
			default:
				return null;
		}
	}
	
	/**
	 * Decrypt using CBC mode. It selects the right algorithm-based engine.
	 * It extracts the ciphertext from the encrypted data (according to its format)
	 * and passes it to {@link decryption.ciphers.BlockCipher#process(org.bouncycastle.crypto.BlockCipher, boolean, byte[], KeyParameter, byte[])}.
	 * 
	 * @param encryptedData data to be decrypted
	 * @param dataFormat encrypted data format
	 * @param keyIvParameters holds key and IV needed for decryption
	 * @return the decrypted data or null if failed
	 */
	private byte[] decryptCBC(byte[] encryptedData, EncryptionFormat dataFormat, KeyIvParameters keyIvParameters) {
		KeyParameter keyParams = new KeyParameter(parameters.key);
		byte[] iv = getIv(encryptedData, dataFormat, keyIvParameters);
		
		if (iv == null) {
			return null;
		}
		org.bouncycastle.crypto.BlockCipher blockCipher = null;
		
		// build the right cipher
		switch ((BlockAlgorithm)algorithm) {
			case AES:
				blockCipher = new CBCBlockCipher(new AESEngine());
				break;
			case CAMELLIA:
				blockCipher = new CBCBlockCipher(new CamelliaEngine());
				break;
			case DES:
				blockCipher = new CBCBlockCipher(new DESEngine());
				break;
			case DES3:
				blockCipher = new CBCBlockCipher(new DESedeEngine());
				break;
			case SERPENT:
				blockCipher = new CBCBlockCipher(new SerpentEngine());
				break;
			case BLOWFISH:
				blockCipher = new CBCBlockCipher(new BlowfishEngine());
				break;
			case IDEA:
				blockCipher = new CBCBlockCipher(new IDEAEngine());
				break;
			case TWOFISH:
				blockCipher = new CBCBlockCipher(new TwofishEngine());
				break;
			default:
				return null;
		}
		try {
			// extracts the ciphertext to make it suitable for processing
			byte[] ciphertext = DataFormatHelper.extractCiphertextEncryption(encryptedData, dataFormat, iv.length);
			if(ciphertext == null) {
				return null;
			}
			return process(blockCipher, false, ciphertext, keyParams, keyIvParameters.iv);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Attempts to get the IV from the parameters or, if this fails, tries to find it within the encrypted data
	 * 
	 * @param encryptedData the encrypted data that may contain the IV
	 * @param dataFormat format of encrypted data
	 * @param keyIvParameters the parameters used to initialize this class
	 * @return the IV, if found, or null
	 */
	private byte[] getIv(byte[] encryptedData, EncryptionFormat dataFormat, KeyIvParameters keyIvParameters) {
		byte[] iv = null;
		if (keyIvParameters.iv != null) {
			iv = keyIvParameters.iv;
		} else {
			iv = DataFormatHelper.extractIvStandardEncryption(encryptedData, dataFormat, keyIvParameters.getIvLengthBytes());
		}
		return iv;
	}

	/**
	 * Decrypt using CTR mode. It selects the right algorithm-based engine.
	 * It extracts the ciphertext from the encrypted data (according to its format)
	 * and passes it to {@link decryption.ciphers.BlockCipher#processCtr(org.bouncycastle.crypto.BlockCipher, boolean, byte[], KeyParameter, byte[])}.
	 * It expects to receive a key and an IV.
	 * 
	 * @param encryptedData data to be decrypted
	 * @param dataFormat encrypted data format
	 * @param keyIvParameters holds key and IV needed for decryption
	 * @return the decrypted data or null if failed
	 * @return
	 */
	private byte[] decryptCTR(byte[] encryptedData, EncryptionFormat dataFormat, KeyIvParameters keyIvParameters) {
		KeyParameter keyParams = new KeyParameter(parameters.key);
		byte[] iv = getIv(encryptedData, dataFormat, keyIvParameters);
		if (iv == null) {
			return null;
		}
		org.bouncycastle.crypto.BlockCipher blockCipher = null;
		switch ((BlockAlgorithm)algorithm) {
			case AES:
				blockCipher = new SICBlockCipher(new AESEngine());
				break;
			case CAMELLIA:
				blockCipher = new SICBlockCipher(new CamelliaEngine());
				break;
			case DES:
				blockCipher = new SICBlockCipher(new DESEngine());
				break;
			case DES3:
				blockCipher = new SICBlockCipher(new DESedeEngine());
				break;
			case SERPENT:
				blockCipher = new SICBlockCipher(new SerpentEngine());
				break;
			case BLOWFISH:
				blockCipher = new SICBlockCipher(new BlowfishEngine());
				break;
			case IDEA:
				blockCipher = new SICBlockCipher(new IDEAEngine());
				break;
			case TWOFISH:
				blockCipher = new SICBlockCipher(new TwofishEngine());
				break;
			default:
				return null;
		}
		try {
			byte[] ciphertext = DataFormatHelper.extractCiphertextEncryption(encryptedData, dataFormat, iv.length);
			if(ciphertext == null) {
				return null;
			}
			return processCtr(blockCipher, false, ciphertext, keyParams, iv);
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
	 * 
	 * @param blockCipher Bouncy Castle block cipher to decrypt with
	 * @param encrypting true in case of encryption, false (default) in case of decryption
	 * @param input the ciphertext
	 * @param key Bouncy Castle wrapper for a key
	 * @param iv the IV to be used in decryption
	 * @return the decryption of input
	 * @throws Exception in case of wrong parameters or input size
	 */
	private byte[] process(org.bouncycastle.crypto.BlockCipher blockCipher, boolean encrypting, byte[] input, KeyParameter key, byte[] iv) throws Exception {
		BufferedBlockCipher cipher = new BufferedBlockCipher(blockCipher);
		
		cipher.init(encrypting, new ParametersWithIV(key, iv));
		byte output[] = new byte[cipher.getOutputSize(input.length)];
		int outputLength = cipher.processBytes(input, 0, input.length, output, 0);
		cipher.doFinal(output, outputLength);
		
		return output;
	}
	
	/**
	 * Just like {@link decryption.ciphers.BlockCipher#process(org.bouncycastle.crypto.BlockCipher, boolean, byte[], KeyParameter, byte[])} at the moment.
	 * 
	 * @param blockCipher
	 * @param encrypting
	 * @param input
	 * @param key
	 * @param iv
	 * @return
	 * @throws Exception
	 * @see decryption.ciphers.BlockCipher#process(org.bouncycastle.crypto.BlockCipher, boolean, byte[], KeyParameter, byte[])
	 */
	private byte[] processCtr(org.bouncycastle.crypto.BlockCipher blockCipher, boolean encrypting, byte[] input, KeyParameter key, byte[] iv) throws Exception {
		BufferedBlockCipher cipher = new BufferedBlockCipher(blockCipher);
		
		cipher.init(encrypting, new ParametersWithIV(key, iv));
		byte output[] = new byte[cipher.getOutputSize(input.length)];
		int outputLength = cipher.processBytes(input, 0, input.length, output, 0);
		cipher.doFinal(output, outputLength);
		
		return output;
	}
	
	
	
}
