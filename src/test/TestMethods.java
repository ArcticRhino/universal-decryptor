package test;

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

import decryption.Constants.Algorithm;
import decryption.Constants.Mode;
import decryption.Decryptor;
import decryption.formats.Library;
import decryption.parameters.KeyAEADParameters;
import utilities.ConsolePrinter;
import utilities.ResultTypes.ByteDataList;
import utilities.ResultTypes.NameIndexedCollection;

public class TestMethods {
	// CHANGE THIS TO THE PATH TO TEST (test included)
	public static String BASE_DIRECTORY = "/home/osboxes/Documenti/Tesi/test";
	
	// password
	public static String PASSWORD = "password1234";
	
	// Key files
	static String KEY256 =          	Paths.get(BASE_DIRECTORY, "key256").toString();
	static String KEY192 =          	Paths.get(BASE_DIRECTORY, "key192").toString();
	static String KEY128 =          	Paths.get(BASE_DIRECTORY, "key128").toString();
	static String KEY64 =           	Paths.get(BASE_DIRECTORY, "key64").toString();
	static String IV128 =				Paths.get(BASE_DIRECTORY, "iv128").toString();
	static String IV96 =        		Paths.get(BASE_DIRECTORY, "iv96").toString();
	static String IV64 = 				Paths.get(BASE_DIRECTORY, "iv64").toString();

	// Base Directories
	static String BOUNCY_BASE_DIRECTORY =  					Paths.get(BASE_DIRECTORY, "bouncy", "enc") + File.separator;
	static String BOTAN_BASE_DIRECTORY =  					Paths.get(BASE_DIRECTORY, "botan", "enc") + File.separator;
	static String CRYPTOPP_BASE_DIRECTORY =					Paths.get(BASE_DIRECTORY, "cryptopp", "enc") + File.separator;
	static String LIBGCRYPT_BASE_DIRECTORY =  				Paths.get(BASE_DIRECTORY, "libgcrypt", "enc") + File.separator;
	static String LIBTOMCRYPT_BASE_DIRECTORY =  			Paths.get(BASE_DIRECTORY, "libtomcrypt", "enc") + File.separator;
	static String NETTLE_BASE_DIRECTORY =  					Paths.get(BASE_DIRECTORY, "nettle", "enc") + File.separator;
	static String OPENSSL_BASE_DIRECTORY =  				Paths.get(BASE_DIRECTORY, "openssl", "enc") + File.separator;
	static String PYCRYPTO_BASE_DIRECTORY =  				Paths.get(BASE_DIRECTORY, "pycrypto", "enc") + File.separator;
	static String PYTHONCRYPTOGRAPHY_BASE_DIRECTORY =  		Paths.get(BASE_DIRECTORY, "pythoncryptography", "enc") + File.separator;
	static String WOLFCRYPT_BASE_DIRECTORY =  				Paths.get(BASE_DIRECTORY, "wolfcrypt", "enc") + File.separator;
	static String TINK_BASE_DIRECTORY =  					Paths.get(BASE_DIRECTORY, "tink", "enc") + File.separator;
	static String CSHARPCRYPTOGRAPHY_BASE_DIRECTORY =  		Paths.get(BASE_DIRECTORY, "csharpcryptography", "enc") + File.separator;
	static String COPENSSL_BASE_DIRECTORY =  				Paths.get(BASE_DIRECTORY, "copenssl", "enc") + File.separator;
	static String GNUPG_BASE_DIRECTORY =  					Paths.get(BASE_DIRECTORY, "gnupg", "enc") + File.separator;
	static String DEFUSE_BASE_DIRECTORY =  					Paths.get(BASE_DIRECTORY, "defuse", "enc") + File.separator;

	// Block
	static String AESCBC =  		"aes256.cbc";
	static String CAMELLIACBC =  	"camellia256.cbc";
	static String AESCTR =  		"aes256.ctr";
	static String DES64CBC =  		"des64.cbc";
	static String DES3192 =  		"des3192.cbc";
	static String IDEA128 =  		"idea128.cbc";
	static String BLOWFISH =  		"blowfish128";

	// Stream
	static String CHACHA20 =  		"chacha20256";
	static String RC4 =  			"rc4256";
	// AEAD
	static String AESGCM =  		"aes256.gcm";
	static String CHACHAPOLY =  	"chachapoly";
	
	// OpenSSL
	static String SHA256 =  		"sha256.";
	static String MD5 =  			"md5.";
	static String PBKDF2 =  		"pbkdf2.";
	
	static String SECRET_DATA = 		Paths.get(BASE_DIRECTORY, "secret").toString();
	static String ADDITIONAL_DATA = 	Paths.get(BASE_DIRECTORY, "additionaldata").toString();
	
	/**
	 * Test the decryptor class. library, algorithm and mode can be null in different combinations:
	 * - library, algorithm, mode
	 * - library, algorithm, null
	 * - library, null, null
	 * - null, algorithm, null
	 * - null, null, null
	 * 
	 * @param encryptedData data to be decrypted
	 * @param key chosen key
	 * @param iv chosen IV
	 * @param additionalData additional data, if relevant
	 * @param library chosen library
	 * @param algorithm chosen algorithm
	 * @param mode chosen mode
	 */
	public static void testDecryptorWithKey(byte[] encryptedData, byte[] key, byte[] iv, byte[] additionalData, Library library, Algorithm algorithm, Mode mode) {
		Decryptor decryptor = new Decryptor(null, key, iv, 0, additionalData, KeyAEADParameters.UNKNOWN);
		if(library == null) {
			if(algorithm == null) {		// both algorithm and library unknown
				NameIndexedCollection<NameIndexedCollection<ByteDataList>> results = decryptor.decryptWithKey(encryptedData);
				for(String libraryName : results.getNames()) {
					ConsolePrinter.printMessage(libraryName + ":\n");
					NameIndexedCollection<ByteDataList> resultsByLibrary = results.getByName(libraryName);
					if(resultsByLibrary == null) {
						break;
					}
					for(String algorithmName : resultsByLibrary.getNames()) {
						ConsolePrinter.printMessage("  " + algorithmName + ":\n");
						ByteDataList resultsByAlgorithm = resultsByLibrary.getByName(algorithmName);
						if(resultsByAlgorithm == null) {
							break;
						}
						for(byte[] decryptedData : resultsByAlgorithm) {
							ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
						}
					}
				}
			} else{	// algorithm is known
				NameIndexedCollection<ByteDataList> results = decryptor.decryptWithKey(encryptedData, algorithm);
				for(String libraryName : results.getNames()) {
					ConsolePrinter.printMessage(libraryName + ":\n");
					ByteDataList resultsPerLibrary = results.getByName(libraryName);
					if(resultsPerLibrary == null) {
						break;
					}
					for(byte[] decryptedData : resultsPerLibrary) {
						ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
					}
				}
			}
		} else {
			if(algorithm == null) {			// only the library is known
				NameIndexedCollection<ByteDataList> results = decryptor.decryptWithKey(encryptedData, library);
				for(String algorithmName : results.getNames()) {
					ConsolePrinter.printMessage(algorithmName + ":\n");
					ByteDataList resultsPerAlgorithm = results.getByName(algorithmName);
					if(resultsPerAlgorithm == null) {
						break;
					}
					for(byte[] decryptedData : resultsPerAlgorithm) {
						ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
					}
				}
			} else {
				if(mode == null) {			// only library and algorithm
					ByteDataList results = decryptor.decryptWithKey(encryptedData, library, algorithm);
					for(byte[] decryptedData : results) {
						ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
					}
				} else {						// library, algorithm and mode are known
					byte[] decryptedData = decryptor.decryptWithKey(encryptedData, library, algorithm, mode);
					ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
				}
			} 
		}
	}
	
	/**
	 * Test the decryptor class. library, algorithm and mode can be null in different combinations:
	 * - library, algorithm, mode
	 * - library, algorithm, null
	 * - library, null, null
	 * - null, algorithm, null
	 * - null, null, null
	 * 
	 * @param encryptedData data to be decrypted
	 * @param key chosen key
	 * @param iv chosen IV
	 * @param additionalData additional data, if relevant
	 * @param library chosen library
	 * @param algorithm chosen algorithm
	 * @param mode chosen mode
	 */
	public static void testDecryptorWithPassword(byte[] encryptedData, String password, byte[] iv, byte[] additionalData, Library library, Algorithm algorithm, Mode mode) {
		Decryptor decryptor = new Decryptor(password, null, iv, 0, additionalData, KeyAEADParameters.UNKNOWN);
		if(library == null) {
			if(algorithm == null) {		// both algorithm and library unknown
				NameIndexedCollection<NameIndexedCollection<List<ByteDataList>>> results = decryptor.decryptWithPassword(encryptedData, null);
				for(String libraryName : results.getNames()) {
					ConsolePrinter.printMessage(libraryName + ":\n");
					NameIndexedCollection<List<ByteDataList>> resultsByLibrary = results.getByName(libraryName);
					if(resultsByLibrary == null) {
						break;
					}
					for(String algorithmName : resultsByLibrary.getNames()) {
						ConsolePrinter.printMessage("  " + algorithmName + ":\n");
						List<ByteDataList> resultsByAlgorithm = resultsByLibrary.getByName(algorithmName);
						if(resultsByAlgorithm == null) {
							break;
						}
						for(ByteDataList decryptedDataList : resultsByAlgorithm) {
							if(decryptedDataList == null) {
								break;
							}
							for(byte[] decryptedData : decryptedDataList) {
								ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
							}
						}
					}
				}
			} else{	// algorithm is known
				NameIndexedCollection<List<ByteDataList>> results = decryptor.decryptWithPassword(encryptedData, algorithm, null);
				for(String libraryName : results.getNames()) {
					ConsolePrinter.printMessage(libraryName + ":\n");
					List<ByteDataList> resultsPerLibrary = results.getByName(libraryName);
					if(resultsPerLibrary == null) {
						break;
					}
					for(ByteDataList decryptedDataList : resultsPerLibrary) {
						if(decryptedDataList == null) {
							break;
						}
						for(byte[] decryptedData : decryptedDataList) {
							ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
						}
					}
				}
			}
		} else {
			if(algorithm == null) {			// only the library is known
				NameIndexedCollection<List<ByteDataList>> results = decryptor.decryptWithPassword(encryptedData, library, null);
				for(String algorithmName : results.getNames()) {
					ConsolePrinter.printMessage(algorithmName + ":\n");
					List<ByteDataList> resultsPerAlgorithm = results.getByName(algorithmName);
					if(resultsPerAlgorithm == null) {
						break;
					}
					for(ByteDataList decryptedDataList : resultsPerAlgorithm) {
						if(decryptedDataList == null) {
							break;
						}
						for(byte[] decryptedData : decryptedDataList) {
							ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
						}
					}
				}
			} else {
				if(mode == null) {			// only library and algorithm
					List<ByteDataList> results = decryptor.decryptWithPassword(encryptedData, library, algorithm, null);
					for(ByteDataList resultsPerMode : results) {
						if(resultsPerMode == null) {
							break;
						}
						for(byte[] decryptedData : resultsPerMode) {
							ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
						}
					}
				} else {						// library, algorithm and mode are known
					ByteDataList results = decryptor.decryptWithPassword(encryptedData, library, algorithm, mode, null);
					for(byte[] decryptedData : results) {
						ConsolePrinter.printMessage("      Decrypted: " + (decryptedData == null ? "null" : new String(decryptedData)));
					}
				}
			} 
		}
	}
}
