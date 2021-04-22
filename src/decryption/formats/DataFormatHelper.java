package decryption.formats;

import decryption.formats.FormatDefinition.AEADFormat;
import decryption.formats.FormatDefinition.EncryptionFormat;

/**
 * Collection of methods used for extracting parts from ciphertexts, with respect to their format defined in {@link decryption.formats.FormatDefinition}.
 * Allows the extraction of ciphertext and IV from encrypted data produced by Standard Encryption
 * and extraction of ciphertext, IV and tag with regards to Authenticated Encryption.
 * Some of these methods are tailored to specific libraries (OpenSSL, GnuPG and Defuse) that feature their particular formats.
 * Users should not call these methods directly, as they are intended to work with the classes in the {@link decryption.ciphers} package
 * 
 * @author Francesco Rositano
 *
 */
public class DataFormatHelper {
	
	/**
	 * Collection of values for extraction of data encrypted with Defuse
	 */
	private static class DefuseFormatValues{
		private static int defuseVersionIndexBytes = 0;
		private static int defuseVersionLengthBytes = 4;
		private static int defuseSaltIndexBytes = defuseVersionIndexBytes + defuseVersionLengthBytes;
		private static int defuseSaltLengthBytes = 32;
		private static int defuseIvIndexBytes = defuseSaltIndexBytes + defuseSaltLengthBytes;
		private static int defuseIvLengthBytes = 16;
		private static int defuseCiphertextIndexBytes = defuseIvIndexBytes + defuseIvLengthBytes;
		private static final int defuseTagLengthBytes = 32;
	}
	
	/**
	 * Extracts the ciphertext from data encrypted with Standard Encryption (Block and Stream algorithms).
	 * 
	 * @param encryptedData
	 * @param dataFormat
	 * @param ivLengthBytes
	 * @return the ciphertext
	 */
	public static byte[] extractCiphertextEncryption(byte[] encryptedData, EncryptionFormat dataFormat, int ivLengthBytes) {
		int ciphertextLength = 0;
		int ciphertextIndex = 0;
		switch(dataFormat) {
			case VANILLA:
			case ADDED_PADDING:
				return encryptedData;
			case CIPHERTEXT_IV:
				ciphertextLength = encryptedData.length - ivLengthBytes;
				ciphertextIndex = 0;
				return extract(encryptedData, ciphertextIndex, ciphertextLength);
			case IV_CIPHERTEXT:
				ciphertextLength = encryptedData.length - ivLengthBytes;
				ciphertextIndex = ivLengthBytes;
				return extract(encryptedData, ciphertextIndex, ciphertextLength);
			case OPENSSL:
				return extractCiphertextEncryptionOpensslKey(encryptedData);
			case GNUPG:
				return encryptedData;
			case DEFUSE_PHP:
				return encryptedData;
			default:
				return encryptedData;
		}
	}
	
	/**
	 * Extracts the IV from data encrypted with Standard Encryption (Block and Stream algorithms), if found.
	 * 
	 * @param encryptedData
	 * @param dataFormat
	 * @param ivLengthBytes
	 * @return the IV
	 */
	public static byte[] extractIvStandardEncryption(byte[] encryptedData, EncryptionFormat dataFormat, int ivLengthBytes) {
		if (ivLengthBytes > encryptedData.length) {
			return null;
		}
		int ivIndex = 0;
		switch(dataFormat) {
			case VANILLA:
				return null;
			case ADDED_PADDING:
				return null;
			case CIPHERTEXT_IV:
				ivIndex = encryptedData.length - ivLengthBytes;
				return extract(encryptedData, ivIndex, ivLengthBytes);
			case IV_CIPHERTEXT:
				ivIndex = 0;
				return extract(encryptedData, ivIndex, ivLengthBytes);
			case OPENSSL:
				return null;
			case GNUPG:
				return null;
			case DEFUSE_PHP:
				return null;
			default:
				return null;
		}
	}
	
	/**
	 * OpenSSL key-encrypted data is pure ciphertext
	 * 
	 * @param encryptedData
	 * @return the ciphertext
	 */
	public static byte[] extractCiphertextEncryptionOpensslKey(byte[] encryptedData) {
		return encryptedData;
	}
	
	/**
	 * Extracts the salt from an OpenSSL password-encrypted byte array.
	 * Password-encrypted data starts with "Salted__" (8 bytes), followed by 8 bytes of salt.
	 * 
	 * @param encryptedData
	 * @return
	 */
	public static byte[] extractSaltEncryptionOpensslPassword(byte[] encryptedData) {
		// Length of "Salted__"
		int constantStringSaltedLength = 8;
		int saltLength = 8;
		return extract(encryptedData, constantStringSaltedLength, saltLength);
	}
	
	/**
	 * Extracts the ciphertext from an OpenSSL password-encrypted byte array.
	 * The ciphertext is after the metadata, that is "Salted__" followed by the salt.
	 * 
	 * @param encryptedData
	 * @return the ciphertext
	 */
	public static byte[] extractCiphertextEncryptionOpensslPassword(byte[] encryptedData) {
		int constantStringSaltedLength = 8;
		int saltLength = 8;
		int metadataLength = constantStringSaltedLength + saltLength;
		int ciphertextLength = encryptedData.length - metadataLength;
		return extract(encryptedData, metadataLength, ciphertextLength);
	}
	
	/**
	 * Extracts the ciphertext from encrypted data in the classic PGP format, the one used by GnuPG.
	 * 
	 * @param encryptedData
	 * @return
	 */
	public static byte[] extractCiphertextEncryptionGnuPGOld(byte[] encryptedData) {
		int metadataLength = 16;
		int ciphertextLength = encryptedData.length - metadataLength;
		return extract(encryptedData, metadataLength, ciphertextLength);
	}
	
	public static byte[] extractSaltDefuse(byte[] encryptedData) {
		return extract(encryptedData, DefuseFormatValues.defuseSaltIndexBytes, DefuseFormatValues.defuseSaltLengthBytes);
	}
	
	public static byte[] extractIvDefuse(byte[] encryptedData) {
		return extract(encryptedData, DefuseFormatValues.defuseIvIndexBytes, DefuseFormatValues.defuseIvLengthBytes);
	}
	
	/**
	 * Extracts the ciphertext from a Defuse-formatted encrypted data.
	 * The format is as follows: VERSION || salt || iv || ciphertext,
	 * where VERSION is a constant
	 * 
	 * @param encryptedData
	 * @return the ciphertext
	 */
	public static byte[] extractCiphertextDefuse(byte[] encryptedData) {
		int ciphertextLengthBytes = encryptedData.length - DefuseFormatValues.defuseTagLengthBytes - DefuseFormatValues.defuseCiphertextIndexBytes - 1;
		return extract(encryptedData, DefuseFormatValues.defuseCiphertextIndexBytes, ciphertextLengthBytes);
	}
	
	public static byte[] extractCiphertextAEAD(byte[] encryptedData, AEADFormat dataFormat, int ivLengthBytes, int tagLengthBytes) {
		int ciphertextLength = 0;
		int ciphertextIndex = 0;
		switch(dataFormat) {
			case SEPARATED:
				return encryptedData;
			case IV_CIPHERTEXT_TAG:
				ciphertextIndex = ivLengthBytes;
				ciphertextLength = encryptedData.length - tagLengthBytes - ivLengthBytes;
				return extract(encryptedData, ciphertextIndex, ciphertextLength);
			case TAG_CIPHERTEXT:
				ciphertextIndex = tagLengthBytes;
				ciphertextLength = encryptedData.length - tagLengthBytes;
				return extract(encryptedData, ciphertextIndex, ciphertextLength);
			case CIPHERTEXT_TAG:
				ciphertextIndex = 0;
				ciphertextLength = encryptedData.length - tagLengthBytes;
				return extract(encryptedData, ciphertextIndex, ciphertextLength);
			case OPENSSL:
			case GNUPG:
			default:
				return null;
		}
	}
	
	public static byte[] extractIvAEAD(byte[] encryptedData, AEADFormat dataFormat, int ivLengthBytes) {
		if (ivLengthBytes > encryptedData.length) {
			return null;
		}
		switch(dataFormat) {
			case IV_CIPHERTEXT_TAG:
				int ivIndex = 0;
				return extract(encryptedData, ivIndex, ivLengthBytes);
			case TAG_CIPHERTEXT:
			case CIPHERTEXT_TAG:
			case OPENSSL:
			case GNUPG:
			case SEPARATED:
			default:
				return null;
		}
	}
	
	public static byte[] extractTagAEAD(byte[] encryptedData, AEADFormat dataFormat, int tagLengthBytes) {
		if (tagLengthBytes > encryptedData.length) {
			return null;
		}
		int tagIndex = 0;
		switch(dataFormat) {
			case IV_CIPHERTEXT_TAG:
				tagIndex = encryptedData.length - tagLengthBytes;
				return extract(encryptedData, tagIndex, tagLengthBytes);
			case TAG_CIPHERTEXT:
				tagIndex = 0;
				return extract(encryptedData, tagIndex, tagLengthBytes);
			case CIPHERTEXT_TAG:
				tagIndex = encryptedData.length - tagLengthBytes;
				return extract(encryptedData, tagIndex, tagLengthBytes);
			case OPENSSL:
			case GNUPG:
			case SEPARATED:
			default:
				return null;
		}
	}
	
	/**
	 * Basic method to extract some bytes from an array.
	 * 
	 * @param input the source array to extract from
	 * @param offset starting index for extraction
	 * @param length number of bytes to extract
	 * @return
	 */
	public static byte[] extract(byte[] input, int offset, int length) {
		if (length <= 0 || offset < 0 || offset + length > input.length)
			return null;
		byte[] output = new byte[length];
		System.arraycopy(input, offset, output, 0, length);
		return output;
	}

}
