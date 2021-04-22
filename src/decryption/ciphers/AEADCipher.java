package decryption.ciphers;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import decryption.Constants.AEADAlgorithm;
import decryption.Constants.AEADMode;
import decryption.formats.DataFormatHelper;
import decryption.formats.FormatDefinition.AEADFormat;
import decryption.parameters.KeyAEADParameters;
import utilities.ConsolePrinter;

/**
 * A {@link decryption.ciphers.Cipher} specialized in working with AEAD algorithms and modes.
 * It works with key, IV and tag length (or tag).
 * If a tag is supplied (or recovered from the encrypted data), it is verified; else, only the decryption occurs.
 * 
 * @author Francesco Rositano
 *
 */
public class AEADCipher {

	protected AEADAlgorithm algorithm;
	protected AEADMode mode;
	protected KeyAEADParameters parameters;

	public AEADCipher(AEADAlgorithm algorithm, AEADMode mode, KeyAEADParameters parameters) {
		this.algorithm = algorithm;
		this.mode = mode;
		this.parameters = parameters;
	}

	/**
	 * Decrypts encrypted data, knowing its format.
	 * This method accepts associated (or additional) data: this is not mandatory, since decryption is the goal.
	 * 
	 * @param encryptedData bytes to decrypt
	 * @param associatedData additional data that does not participate in decryption, although it is needed for verification
	 * @param dataFormat format of encryptedData
	 * @return the decryption of encryptedData, or null if failed
	 */
	public byte[] decrypt(byte[] encryptedData, byte[] associatedData, AEADFormat dataFormat) {
		// try to get the IV; if it fails, then return null
		byte[] iv = getIv(encryptedData, parameters, dataFormat);
		if(iv == null) {
			ConsolePrinter.printMessage("Unable to recover an iv");
			return null;
		}
		// try to get the tag; if it fails, integrity will not be verified but decryption will still happen
		int ivLengthBytes = iv.length;
		int tagLengthBytes = parameters.getTagSizeBytes();
		byte[] tag = getTag(encryptedData, parameters, dataFormat);
		if(tag == null) {
			ConsolePrinter.printMessage("Unable to recover the tag: data integrity will not be verified");
		}
		// try to extract the ciphertext; if it fails, then return null
		byte[] ciphertext = DataFormatHelper.extractCiphertextAEAD(encryptedData, dataFormat, ivLengthBytes, tagLengthBytes);
		if(ciphertext == null) {
			ConsolePrinter.printMessage("Unable to recover the ciphertext");
			return null;
		}
		
		// delegate decryption to the right method
		AEADFormat AEADformat = (AEADFormat)dataFormat;
		switch ((AEADAlgorithm)algorithm) {
			case AES_AEAD:
				switch ((AEADMode)mode) {
					case NONE:
						return null;
					case GCM:
						return decryptAesGCM(ciphertext, tag, iv, tagLengthBytes, associatedData);
					case CCM:
						return decryptAesCCM(ciphertext, tag, iv, tagLengthBytes, associatedData);
					case EAX:
						return decryptAesEAX(ciphertext, tag, iv, tagLengthBytes, associatedData);
				}
				break;
			// this algorithm requires no mode
			case CHACHA20POLY1305:
				return decryptChaCha20Poly1305(ciphertext, tag, iv, tagLengthBytes, associatedData);
			default:
				return null;
		}
		return null;
	}	

	/**
	 * Tries to get the IV, first from the parameters supplied by the user, then from the encrypted data.
	 * 
	 * @param encryptedData
	 * @param parameters
	 * @param dataFormat format of encryptedData
	 * @return the IV, if recovered, else null
	 */
	private byte[] getIv(byte[] encryptedData, KeyAEADParameters parameters, AEADFormat dataFormat) {
		byte[] iv = null;
		if(parameters != null && parameters.iv != null) {
			iv = parameters.iv;
		} else {
			iv = DataFormatHelper.extractIvAEAD(encryptedData, dataFormat, parameters.getIvLengthBytes());
		}
		return iv;
	}
	
	/**
	 * Tries to get the tag, first from the parameters supplied by the user, then from the encrypted data.
	 * 
	 * @param encryptedData
	 * @param parameters
	 * @param dataFormat format of encryptedData
	 * @return the tag, if recovered, else null
	 */
	private byte[] getTag(byte[] encryptedData, KeyAEADParameters parameters, AEADFormat dataFormat) {
		byte[] tag = null;
		if(parameters != null && parameters.tag != null) {
			tag = parameters.tag;
		} else {
			ConsolePrinter.printMessage("Tag length: " + parameters.getTagSizeBytes());
			tag = DataFormatHelper.extractTagAEAD(encryptedData, dataFormat, parameters.getTagSizeBytes());
		}
		return tag;
	}

	/**
	 * Prepares a Bouncy Castle GCM cipher,
	 * then passes it to {@link decryption.ciphers.AEADCipher#process(org.bouncycastle.crypto.modes.AEADCipher, byte[], byte[], int, AEADParameters)} for decryption.
	 * 
	 * @param ciphertext the extracted ciphertext
	 * @param tag the tag, can be null
	 * @param iv
	 * @param tagLengthBytes length of the tag, in bytes
	 * @param associatedData associated (or additional) data for integrity verification
	 * @return decryption of ciphertext
	 */
	private byte[] decryptAesGCM(byte[] ciphertext, byte[] tag, byte[] iv, int tagLengthBytes, byte[] associatedData) {
		
		GCMBlockCipher gcmCipher = new GCMBlockCipher(new AESEngine());
		AEADParameters aeadParameters = buildAEADParameters(parameters, associatedData);
		
		return process(gcmCipher, ciphertext, tag, tagLengthBytes, aeadParameters);
	}
	
	/**
	 * Prepares a Bouncy Castle CCM cipher,
	 * then passes it to {@link decryption.ciphers.AEADCipher#process(org.bouncycastle.crypto.modes.AEADCipher, byte[], byte[], int, AEADParameters)} for decryption.
	 * 
	 * @param ciphertext the extracted ciphertext
	 * @param tag the tag, can be null
	 * @param iv
	 * @param tagLengthBytes length of the tag, in bytes
	 * @param associatedData associated (or additional) data for integrity verification
	 * @return decryption of ciphertext
	 */
	private byte[] decryptAesCCM(byte[] ciphertext, byte[] tag, byte[] iv, int tagLengthBytes, byte[] associatedData) {
		
		CCMBlockCipher ccmCipher = new CCMBlockCipher(new AESEngine());
		AEADParameters aeadParameters = buildAEADParameters(parameters, associatedData);
		
		return process(ccmCipher, ciphertext, tag, tagLengthBytes, aeadParameters);
	}
	
	/**
	 * Prepares a Bouncy Castle EAX cipher,
	 * then passes it to {@link decryption.ciphers.AEADCipher#process(org.bouncycastle.crypto.modes.AEADCipher, byte[], byte[], int, AEADParameters)} for decryption.
	 * 
	 * @param ciphertext the extracted ciphertext
	 * @param tag the tag, can be null
	 * @param iv
	 * @param tagLengthBytes length of the tag, in bytes
	 * @param associatedData associated (or additional) data for integrity verification
	 * @return decryption of ciphertext
	 */
	private byte[] decryptAesEAX(byte[] ciphertext, byte[] tag, byte[] iv, int tagLengthBytes, byte[] associatedData) {
		
		EAXBlockCipher eaxCipher = new EAXBlockCipher(new AESEngine());
		AEADParameters aeadParameters = buildAEADParameters(parameters, associatedData);
		
		return process(eaxCipher, ciphertext, tag, tagLengthBytes, aeadParameters);
	}
	
	/**
	 * Prepares a Bouncy Castle ChaCha20-Poly1305 cipher,
	 * then passes it to {@link decryption.ciphers.AEADCipher#process(org.bouncycastle.crypto.modes.AEADCipher, byte[], byte[], int, AEADParameters)} for decryption.
	 * 
	 * @param ciphertext the extracted ciphertext
	 * @param tag the tag, can be null
	 * @param iv
	 * @param tagLengthBytes length of the tag, in bytes
	 * @param associatedData associated (or additional) data for integrity verification
	 * @return decryption of ciphertext
	 */
	private byte[] decryptChaCha20Poly1305(byte[] ciphertext, byte[] tag, byte[] iv, int tagLengthBytes, byte[] associatedData) {
		
		ChaCha20Poly1305 chachaPolyCipher = new ChaCha20Poly1305();
		AEADParameters aeadParameters = buildAEADParameters(parameters, associatedData);
		
		return process(chachaPolyCipher, ciphertext, tag, tagLengthBytes, aeadParameters);
	}
	
	/**
	 * Generates a Bouncy Castle parameter-wrapping object, in order to work with a Bouncy Castle cipher.
	 * 
	 * @param parameters user supplied parameters
	 * @param associatedData
	 * @return a Bouncy Castle bundle of parameters (key, tag length in bits, iv, associated data)
	 */
	private AEADParameters buildAEADParameters(KeyAEADParameters parameters, byte[] associatedData) {
		return new AEADParameters(new KeyParameter(parameters.key), parameters.getTagSizeBits(), parameters.iv, associatedData);
	}
	
	/**
	 * Converts a ciphertext and tag into encrypted data complying with the Bouncy Castle AEAD data format (ciphertext || tag). 
	 * 
	 * @param ciphertext the pure ciphertext, extracted from the encrypted data
	 * @param tag
	 * @return ciphertext || tag
	 */
	private byte[] buildBouncyCastleEncryptedData(byte[] ciphertext, byte[] tag) {
		if(ciphertext == null || tag == null) {
			return null;
		}
		byte[] bouncyData = new byte[ciphertext.length + tag.length];
		System.arraycopy(ciphertext, 0, bouncyData, 0, ciphertext.length);
		System.arraycopy(tag, 0, bouncyData, ciphertext.length, tag.length);
		return bouncyData;
	}

	/**
	 * Processes encrypted data with the supplied Bouncy Castle AEAD cipher.
	 * 
	 * @param cipher Bouncy Castle cipher
	 * @param ciphertext pure ciphertext
	 * @param tag
	 * @param tagLengthBytes
	 * @param parameters Bouncy Castle parameters
	 * @return decryption of ciphertext
	 */
	private byte[] process(org.bouncycastle.crypto.modes.AEADCipher cipher, byte[] ciphertext, byte[] tag, int tagLengthBytes, AEADParameters parameters) {
		// if tag is available, integrity will be verified
		boolean isTagAvailable = tag != null;
		byte[] input = null;
		// Bouncy Castle accepts data in the format (ciphertext || tag);
		// if the tag is null, a dummy tag of zeroes is constructed and appended to the ciphertext
		if(!isTagAvailable) {
			byte[] dummyTag = new byte[tagLengthBytes];
			for(int i = 0; i < tagLengthBytes; i++) {
				dummyTag[i] = 0x00;
			}
			input = buildBouncyCastleEncryptedData(ciphertext, dummyTag);
		} else {
			input = buildBouncyCastleEncryptedData(ciphertext, tag);
		}
		byte[] output = new byte[input.length];
		
		try {
			cipher.init(false, parameters);
			int outputLength = cipher.processBytes(input, 0, input.length, output, 0);
			// cipher.doFinal writes the output and verifies the tag; in case of dummy (or wrong) tag, an exception will throw but decryption will still occur
			cipher.doFinal(output, outputLength);
			return output;
		} catch (IllegalStateException e) {
			System.out.println("Process catch exception");
			e.printStackTrace();
			return null;
		} catch (InvalidCipherTextException e) {
			System.out.println("Process catch exception");
			e.printStackTrace();
			return output;
		} catch(Exception e) {
			e.printStackTrace();
			return output;
		}
	}
}
