package decryption;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import decryption.Constants.AEADAlgorithm;
import decryption.Constants.AEADMode;
import decryption.Constants.Algorithm;
import decryption.Constants.BlockAlgorithm;
import decryption.Constants.EncryptionMode;
import decryption.Constants.Mode;
import decryption.Constants.StreamAlgorithm;
import decryption.ciphers.AEADCipher;
import decryption.ciphers.BlockCipher;
import decryption.ciphers.PasswordCipher;
import decryption.ciphers.StreamCipher;
import decryption.formats.Library;
import decryption.parameters.KeyAEADParameters;
import decryption.parameters.KeyIvCounterParameters;
import decryption.parameters.KeyIvParameters;
import utilities.ConsolePrinter;
import utilities.FileUtilities;
import utilities.ResultTypes.ByteDataList;
import utilities.ResultTypes.NameIndexedCollection;

/**
 * The main class for decryption. This class was designed to decrypt with flexibility:
 * users may enter every input and parameter they know, including the supposed algorithm, mode and library.
 * It makes use of the ciphers defined in {@link decryption.ciphers}, while data and parameters format are managed by {@link decryption.formats.Library}
 * <p>
 * Users should check for null value of every byte[], ByteDataList and NameIndexedCollection resulting from these functions.
 * <p>
 * WARNING: At the moment, this is not optimized with respect to memory usage.
 * 
 * @author Francesco Rositano
 *
 */
public class Decryptor {
	
	public String password;
	public byte[] key;
	public byte[] iv;
	public int counterValue;
	public byte[] counterBytes;
	public byte[] associatedData;
	public byte[] tag;
	public int tagLengthBytes;
	
	public Decryptor(String password, byte[] key, byte[] iv) {
		this(password, key, iv, -1, null, null);
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, int counter) {
		this(password, key, iv, counter, null, null);
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, int counter, byte[] associatedData) {
		this(password, key, iv, counter, associatedData, null);
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, int counter, byte[] associatedData, byte[] tag) {
		this.password = password;
		this.key = key;
		this.iv = iv;
		this.counterValue = counter;
		this.associatedData = associatedData;
		this.tag = tag;
		if(tag != null) {
			this.tagLengthBytes = tag.length;
		}
		counterBytes = null;
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, int counter, byte[] associatedData, int tagLengthBytes) {
		this.password = password;
		this.key = key;
		this.iv = iv;
		this.counterValue = counter;
		this.associatedData = associatedData;
		this.tag = null;
		this.tagLengthBytes = tagLengthBytes;
		counterBytes = null;
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, byte[] counter) {
		this(password, key, iv, counter, null, null);
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, byte[] counter, byte[] associatedData) {
		this(password, key, iv, counter, associatedData, null);
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, byte[] counter, byte[] associatedData, byte[] tag) {
		this.password = password;
		this.key = key;
		this.iv = iv;
		this.counterBytes = counter;
		this.associatedData = associatedData;
		this.tag = tag;
		if(tag != null) {
			this.tagLengthBytes = tag.length;
		}
		counterValue = -1;
	}
	
	public Decryptor(String password, byte[] key, byte[] iv, byte[] counter, byte[] associatedData, int tagLengthBytes) {
		this.password = password;
		this.key = key;
		this.iv = iv;
		this.counterBytes = counter;
		this.associatedData = associatedData;
		this.tag = null;
		this.tagLengthBytes = tagLengthBytes;
		counterValue = -1;
	}
	
	/**
	 * Out of the algorithms and modes considered, only RC4 does not need an IV
	 * 
	 * @param algorithm
	 * @param mode
	 * @return true if this combination of algorithm and mode requires an IV
	 */
	private boolean isIvNeeded(Algorithm algorithm, Mode mode) {
		// At the moment, only RC4 does not need an Iv
		return algorithm != StreamAlgorithm.RC4;
	}
	
	/*
	 *-------------------DECRYPTION WITH KEY-------------------
	 */
	
	/**
	 * Decrypts knowing library, algorithm and mode. This the base for all other methods of this class.
	 * 
	 * 
	 * @param encryptedData data to be decrypted
	 * @param library the chosen library for decryption, supposedly the one used in encryption
	 * @param algorithm the chosen algorithm
	 * @param mode the chosen algorithm
	 * @return the decryption of encryptedData, or null if failed
	 */
	public byte[] decryptWithKey(byte[] encryptedData, Library library, Algorithm algorithm, Mode mode) {
		
		// if the library does not support this algorithm or mode, decryption makes no sense
		if (!library.supportsAlgorithm(algorithm)) {
			ConsolePrinter.printMessage("This library does not support this algorithm");
			return null;
		}
		if (!library.supportsMode(mode)) {
			ConsolePrinter.printMessage("This library does not support this mode");
			return null;
		}
		
		boolean isStandardEncryption = !(algorithm instanceof AEADAlgorithm);
		// Cannot decrypt if:
		// - I don't have a key
		if(key == null) {
			ConsolePrinter.printMessage("Key was not provided");
			return null;
		}
		// - if I need an IV, I don't have it and I cannot recover it from the encrypted data
		if(iv == null && isIvNeeded(algorithm, mode) && !library.formatContainsIv(isStandardEncryption)) {
			ConsolePrinter.printMessage("Unable to retrieve iv");
			return null;
		}
		// decide the right Cipher for decryption
		byte[] decryptedData = null;
		// if Block or Stream algorithm
		if(isStandardEncryption) {
			if(algorithm instanceof BlockAlgorithm && mode instanceof EncryptionMode) {
				// in case of CTR, check if the IV is in the right format
				if(((EncryptionMode)mode) == EncryptionMode.CTR) {
					KeyIvParameters params = library.formatCTRParametersIfNeeded(iv, counterValue, counterBytes);
					if(params != null) {
						BlockCipher blockCipher = new BlockCipher((BlockAlgorithm)algorithm, (EncryptionMode)mode, new KeyIvParameters(key, params.iv));
						decryptedData = blockCipher.decrypt(encryptedData, library.encryptionFormat);
					} else {
						BlockCipher blockCipher = new BlockCipher((BlockAlgorithm)algorithm, (EncryptionMode)mode, new KeyIvParameters(key, iv));
						decryptedData = blockCipher.decrypt(encryptedData, library.encryptionFormat);
					}
				} else {
					BlockCipher blockCipher = new BlockCipher((BlockAlgorithm)algorithm, (EncryptionMode)mode, new KeyIvParameters(key, iv));
					decryptedData = blockCipher.decrypt(encryptedData, library.encryptionFormat);
				}
			} else if(algorithm instanceof StreamAlgorithm) {
				// in case of ChaCha, check if nonce and counter are in the right format
				if((StreamAlgorithm)algorithm == StreamAlgorithm.CHACHA20) {
					KeyIvCounterParameters params = library.formatChaChaParametersIfNeeded(iv, counterValue);
					if(params != null) {
						System.out.print("New parameters --- counter: " + params.getCounterInt());
						System.out.print(" / New parameters --- iv: ");
						ConsolePrinter.printBytes(params.iv);
						StreamCipher streamCipher = new StreamCipher((StreamAlgorithm)algorithm, new KeyIvCounterParameters(key, params.iv, params.getCounterInt()));
						decryptedData = streamCipher.decrypt(encryptedData, library.encryptionFormat);
					}else {
						StreamCipher streamCipher = new StreamCipher((StreamAlgorithm)algorithm, new KeyIvCounterParameters(key, iv, counterValue));
						decryptedData = streamCipher.decrypt(encryptedData, library.encryptionFormat);
					}
				}else {
					StreamCipher streamCipher = new StreamCipher((StreamAlgorithm)algorithm, new KeyIvCounterParameters(key, iv, counterValue));
					decryptedData = streamCipher.decrypt(encryptedData, library.encryptionFormat);
				}
			}
			// if AEAD algorithm
		} else if(algorithm instanceof AEADAlgorithm && mode instanceof AEADMode) {
			KeyAEADParameters params;
			if(tag == null) {
				ConsolePrinter.printMessage("Tag was not provided, an attempt to find it within the encrypted data will be done");
				if(tagLengthBytes > 0) {
					params = new KeyAEADParameters(key, iv, tagLengthBytes);
				} else {
					params = new KeyAEADParameters(key, iv, library.getDefaultTagLengthBytes());
				}
			} else{
				params = new KeyAEADParameters(key, iv, tag);
			}
			AEADCipher aeadCipher = new AEADCipher((AEADAlgorithm)algorithm, (AEADMode)mode, params);
			decryptedData = aeadCipher.decrypt(encryptedData, associatedData, library.aeadFormat);
		}
		return decryptedData;
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithKey(byte[], Library, Algorithm, Mode)
	 * 
	 * @param encryptedFilename
	 * @param library
	 * @param algorithm
	 * @param mode
	 * @return decryption of the file at encryptedFilename
	 */
	public byte[] decryptWithKey(String encryptedFilename, Library library, Algorithm algorithm, Mode mode) {
		return decryptWithKey(FileUtilities.readFile(encryptedFilename), library, algorithm, mode);
	}
	
	/**
	 * Decrypts knowing only library and algorithm: tries every mode supported by the library.
	 * The result is a list of byte arrays.
	 * 
	 * @param encryptedData
	 * @param library
	 * @param algorithm
	 * @return a list of decryptions
	 */
	public ByteDataList decryptWithKey(byte[] encryptedData, Library library, Algorithm algorithm) {
		if(!library.supportsAlgorithm(algorithm)) {
			ConsolePrinter.printMessage(library.name + " does not support this algorithm");
			return null;
		}
		ArrayList<byte[]> decryptedDataList = new ArrayList<byte[]>();
		if(algorithm instanceof BlockAlgorithm) {
			for(EncryptionMode mode : library.encryptionModes) {
				if(mode != EncryptionMode.NONE) {
					decryptedDataList.add(decryptWithKey(encryptedData, library, algorithm, mode));
				}
			}
		} else if(algorithm instanceof AEADAlgorithm) {
			if(((AEADAlgorithm)algorithm).requiresMode()) {
				for(AEADMode mode : library.aeadmodes) {
					if(mode != AEADMode.NONE) {
						decryptedDataList.add(decryptWithKey(encryptedData, library, algorithm, mode));
					}
				}
			} else {
				decryptedDataList.add(decryptWithKey(encryptedData, library, algorithm, AEADMode.NONE));
			}
		} else if(algorithm instanceof StreamAlgorithm) {
			decryptedDataList.add(decryptWithKey(encryptedData, library, algorithm, EncryptionMode.NONE));
		} else {
			return null;
		}
		return new ByteDataList(decryptedDataList);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithKey(byte[], Library, Algorithm)
	 * 
	 * @param encryptedFilename
	 * @param library
	 * @param algorithm
	 * @return a list of decryptions of the file at encryptedFilename
	 */
	public ByteDataList decryptWithKey(String encryptedFilename, Library library, Algorithm algorithm){
		return decryptWithKey(FileUtilities.readFile(encryptedFilename), library, algorithm);
	}
	
	/**
	 * Decrypts knowing only the library.
	 * It tries every supported algorithm and mode. The result is an algorithm-indexed collection of lists of decryptions.
	 * Each list corresponds to decryptions using an algorithm with each supported mode.
	 * 
	 * @param encryptedData
	 * @param library
	 * @return a collection of decryptions
	 */
	public NameIndexedCollection<ByteDataList> decryptWithKey(byte[] encryptedData, Library library) {
		HashMap<String, ByteDataList> algorithmIndexedDecryptedDataLists = new HashMap<String, ByteDataList>();
		for(BlockAlgorithm blockAlg : library.blockAlgorithms) {
			if(blockAlg != BlockAlgorithm.NONE) {
				ByteDataList decryptedDataList = decryptWithKey(encryptedData, library, blockAlg);
				algorithmIndexedDecryptedDataLists.put(blockAlg.name(), decryptedDataList);
			}
		}
		for(StreamAlgorithm streamALg : library.streamAlgorithms) {
			if(streamALg != StreamAlgorithm.NONE) {
				ByteDataList decryptedDataList = decryptWithKey(encryptedData, library, streamALg);
				algorithmIndexedDecryptedDataLists.put(streamALg.name(), decryptedDataList);
			}
		}
		for(AEADAlgorithm AEADAlg : library.aeadAlgorithms) {
			if(AEADAlg != AEADAlgorithm.NONE) {
				ByteDataList decryptedDataList = decryptWithKey(encryptedData, library, AEADAlg);
				algorithmIndexedDecryptedDataLists.put(AEADAlg.name(), decryptedDataList);
			}
		}
		return new NameIndexedCollection<ByteDataList>(algorithmIndexedDecryptedDataLists);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithKey(byte[], Library)
	 * 
	 * @param encryptedFilename
	 * @param library
	 * @return a collection of decryptions of the file at encryptedFilename
	 */
	public NameIndexedCollection<ByteDataList> decryptWithKey(String encryptedFilename, Library library){
		return decryptWithKey(FileUtilities.readFile(encryptedFilename), library);
	}
	
	/**
	 * Decrypts knowing algorithm and mode. It tries every library that supports them both.
	 * The result is a collection of decryption indexed by library name.
	 * 
	 * @param encryptedData
	 * @param algorithm
	 * @param mode
	 * @return a collection of decryptions
	 */
	public NameIndexedCollection<byte[]> decryptWithKey(byte[] encryptedData, Algorithm algorithm, Mode mode) {
		HashMap<String, byte[]> libraryIndexedDecryptedDataLists = new HashMap<String, byte[]>();
		for (Library library : Library.libraries.values()) {
			if(library.supportsAlgorithm(algorithm) && library.supportsMode(mode)) {
				byte[] decryptedData = decryptWithKey(encryptedData, library, algorithm, mode);
				libraryIndexedDecryptedDataLists.put(library.name, decryptedData);
			}
		}
		return new NameIndexedCollection<byte[]>(libraryIndexedDecryptedDataLists);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithKey(byte[], Algorithm, Mode)
	 * 
	 * @param encryptedFilename
	 * @param algorithm
	 * @param mode
	 * @return a collection of decryptions of the file at encryptedFilename
	 */
	public NameIndexedCollection<byte[]> decryptWithKey(String encryptedFilename, Algorithm algorithm, Mode mode){
		return decryptWithKey(FileUtilities.readFile(encryptedFilename), algorithm, mode);
	}
	
	/**
	 * Decrypts knowing only the algorithm. For each library that supports this algorithm, it tries every supported mode.
	 * The result is a collection, indexed by library name, of lists of decryption, one for every suitable mode.
	 * 
	 * @param encryptedData
	 * @param algorithm
	 * @return a collection of lists of decryptions
	 */
	public NameIndexedCollection<ByteDataList> decryptWithKey(byte[] encryptedData, Algorithm algorithm) {
		HashMap<String, ByteDataList> libraryIndexedDecryptedDataLists = new HashMap<String, ByteDataList>();
		for (Library library : Library.libraries.values()) {
			if(library.supportsAlgorithm(algorithm)) {
				ByteDataList decryptedDataList = decryptWithKey(encryptedData, library, algorithm);
				libraryIndexedDecryptedDataLists.put(library.name, decryptedDataList);
			}
		}
		return new NameIndexedCollection<ByteDataList>(libraryIndexedDecryptedDataLists);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithKey(byte[], Algorithm)
	 * 
	 * @param encryptedFilename
	 * @param algorithm
	 * @return a collection of lists of decryptions of the file at encryptedFilename
	 */
	public NameIndexedCollection<ByteDataList> decryptWithKey(String encryptedFilename, Algorithm algorithm){
		return decryptWithKey(FileUtilities.readFile(encryptedFilename), algorithm);
	}
	
	/**
	 * Decrypts with no knowledge about what was used during encryption, besides key, IV and other parameters.
	 * For each library, it tries every algorithm with every mode supported by the latter.
	 * The result is a collection, indexed by library name, of collections, indexed by algorithm, of lists of decryption, one decryption per mode.
	 * 
	 * @param encryptedData
	 * @return a composite collection of decryptions
	 */
	public NameIndexedCollection<NameIndexedCollection<ByteDataList>> decryptWithKey(byte[] encryptedData) {
		HashMap<String, NameIndexedCollection<ByteDataList>> libraryIndexedCollection = new HashMap<String, NameIndexedCollection<ByteDataList>>();
		for (Library library : Library.libraries.values()) {
			NameIndexedCollection<ByteDataList> algorithmIndexedDecryptedDataLists = decryptWithKey(encryptedData, library);
			libraryIndexedCollection.put(library.name, algorithmIndexedDecryptedDataLists);
		}
		return new NameIndexedCollection<NameIndexedCollection<ByteDataList>>(libraryIndexedCollection);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithKey(byte[])
	 * 
	 * @param encryptedFilename
	 * @return a composite collection of decryptions of the file at encryptedFilename
	 */
	public NameIndexedCollection<NameIndexedCollection<ByteDataList>> decryptWithKey(String encryptedFilename){
		return decryptWithKey(FileUtilities.readFile(encryptedFilename));
	}
	
	/*
	 *-------------------DECRYPTION WITH PASSWORD-------------------
	 */
	
	/**
	 * Decrypts with password, knowing library, algorithm and mode used for encryption.
	 * Concerning OpenSSL, if openSSLKeyDerivationMethod is null every possible key generation method is tested, else, only the one provided.
	 * Nevertheless, for flexibility, the result is a list so that it can accomodate decryptions with every key generation method.
	 * 
	 * @param encryptedData
	 * @param library
	 * @param algorithm
	 * @param mode
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a list of decryptions; possibly with one element
	 */
	public ByteDataList decryptWithPassword(byte[] encryptedData, Library library, Algorithm algorithm, Mode mode, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		ArrayList<byte[]> decryptions = new ArrayList<byte[]>();
		if (!library.supportsPassword) {
			ConsolePrinter.printMessage("This library does not support passwords");
			return null;
		}
		if (!library.supportsAlgorithm(algorithm)) {
			ConsolePrinter.printMessage("This library does not support this algorithm");
			return null;
		}
		if (!(algorithm instanceof StreamAlgorithm) && !library.supportsMode(mode)) {
			ConsolePrinter.printMessage("This library does not support this mode");
			return null;
		}
		if(library.name.equals(Library.LIBRARY_OPENSSL) && openSSLKeyDerivationMethod == null) {
			for(OpenSSLDecryptor.KeyDerivationMethod keyDerivationMethod : OpenSSLDecryptor.KeyDerivationMethod.values()) {
				PasswordCipher cipher = new PasswordCipher(algorithm, mode, password, keyDerivationMethod);
				decryptions.add(cipher.decrypt(encryptedData, library.encryptionFormat));
			}
		} else {
			PasswordCipher cipher = new PasswordCipher(algorithm, mode, password, openSSLKeyDerivationMethod);
			decryptions.add(cipher.decrypt(encryptedData, library.encryptionFormat));
		}
		return new ByteDataList(decryptions);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithPassword(byte[], Library, Algorithm, Mode, decryption.OpenSSLDecryptor.KeyDerivationMethod)
	 * 
	 * @param encryptedFilename
	 * @param library
	 * @param algorithm
	 * @param mode
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a list of decryptions of the file at encryptedFilename; possibly with one element
	 */
	public ByteDataList decryptWithPassword(String encryptedFilename, Library library, Algorithm algorithm, Mode mode, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		return decryptWithPassword(FileUtilities.readFile(encryptedFilename), library, algorithm, mode, openSSLKeyDerivationMethod);
	}
	
	/**
	 * Decrypts with a password, knowing library and algorithm.
	 * The result is a list of decryptions, one for each mode supported by the library.
	 * 
	 * @param encryptedData
	 * @param library
	 * @param algorithm
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a list of lists of decryptions
	 */
	public List<ByteDataList> decryptWithPassword(byte[] encryptedData, Library library, Algorithm algorithm, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		if(!library.supportsAlgorithm(algorithm)) {
			ConsolePrinter.printMessage(library.name + " does not support this algorithm");
			return null;
		}
		ArrayList<ByteDataList> results = new ArrayList<ByteDataList>();
		
		if(algorithm instanceof BlockAlgorithm) {
			for(EncryptionMode mode : library.encryptionModes) {
				if(mode != EncryptionMode.NONE) {
					results.add(decryptWithPassword(encryptedData, library, algorithm, mode, openSSLKeyDerivationMethod));
				}
			}
		} else if(algorithm instanceof AEADAlgorithm) {
			if(((AEADAlgorithm)algorithm).requiresMode()) {
				for(AEADMode mode : library.aeadmodes) {
					if(mode != AEADMode.NONE) {
						results.add(decryptWithPassword(encryptedData, library, algorithm, mode, openSSLKeyDerivationMethod));
					}
				}
			} else {
				results.add(decryptWithPassword(encryptedData, library, algorithm, AEADMode.NONE, openSSLKeyDerivationMethod));
			}
		} else if(algorithm instanceof StreamAlgorithm) {
			results.add(decryptWithPassword(encryptedData, library, algorithm, null, openSSLKeyDerivationMethod));
		} else {
			return null;
		}
		return results;
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithPassword(byte[], Library, Algorithm, decryption.OpenSSLDecryptor.KeyDerivationMethod)
	 * 
	 * @param encryptedFilename
	 * @param library
	 * @param algorithm
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a list of lists of decryptions of the file at encryptedFilename
	 */
	public List<ByteDataList> decryptWithPassword(String encryptedFilename, Library library, Algorithm algorithm, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		return decryptWithPassword(FileUtilities.readFile(encryptedFilename), library, algorithm, openSSLKeyDerivationMethod);
	}
	
	/**
	 * Decrypts with password knowing the algorithm.
	 * The result is a library-indexed collection of lists of lists of decryptions; the latter lists could possibly include only one element.
	 * 
	 * @param encryptedData
	 * @param algorithm
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a collection of decryptions indexed by library name
	 */
	public NameIndexedCollection<List<ByteDataList>> decryptWithPassword(byte[] encryptedData, Algorithm algorithm, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		HashMap<String, List<ByteDataList>> results = new HashMap<String, List<ByteDataList>>();
		List<Library> passwordLibraries = Library.getPasswordEnabledLibraries();
		for(Library library : passwordLibraries) {
			List<ByteDataList> libraryDecryptions = decryptWithPassword(encryptedData, library, algorithm, openSSLKeyDerivationMethod);
			results.put(library.name, libraryDecryptions);
		}
		return new NameIndexedCollection<List<ByteDataList>>(results);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithPassword(byte[], Algorithm, decryption.OpenSSLDecryptor.KeyDerivationMethod)
	 * 
	 * @param encryptedFilename
	 * @param algorithm
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a collection of decryptions of the file at encryptedFilename, indexed by library name
	 */
	public NameIndexedCollection<List<ByteDataList>> decryptWithPassword(String encryptedFilename, Algorithm algorithm, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		return decryptWithPassword(FileUtilities.readFile(encryptedFilename), algorithm, openSSLKeyDerivationMethod);
	}
	
	/**
	 * Decrypts with password knowing the library.
	 * 
	 * @param encryptedData
	 * @param library
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return
	 */
	public NameIndexedCollection<List<ByteDataList>> decryptWithPassword(byte[] encryptedData, Library library, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		HashMap<String, List<ByteDataList>> results = new HashMap<String, List<ByteDataList>>();
		for(BlockAlgorithm blockAlg : library.blockAlgorithms) {
			List<ByteDataList> algorithmIndexedDecryptions = decryptWithPassword(encryptedData, library, blockAlg, openSSLKeyDerivationMethod);
			results.put(blockAlg.name() ,algorithmIndexedDecryptions);
		}
		for(StreamAlgorithm streamAlg : library.streamAlgorithms) {
			List<ByteDataList> algorithmIndexedDecryptions = decryptWithPassword(encryptedData, library, streamAlg, openSSLKeyDerivationMethod);
			results.put(streamAlg.name() ,algorithmIndexedDecryptions);
		}
		for(AEADAlgorithm aeadAlg : library.aeadAlgorithms) {
			List<ByteDataList> algorithmIndexedDecryptions = decryptWithPassword(encryptedData, library, aeadAlg, openSSLKeyDerivationMethod);
			results.put(aeadAlg.name() ,algorithmIndexedDecryptions);
		}
		return new NameIndexedCollection<List<ByteDataList>>(results);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithPassword(byte[], Library, decryption.OpenSSLDecryptor.KeyDerivationMethod)
	 * 
	 * @param encryptedFilename
	 * @param library
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return
	 */
	public NameIndexedCollection<List<ByteDataList>> decryptWithPassword(String encryptedFilename, Library library, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		return decryptWithPassword(FileUtilities.readFile(encryptedFilename), library, openSSLKeyDerivationMethod);
	}
	
	/**
	 * Decrypts with password, with no knowledge on the encryption method, besides input and parameters.
	 * The result is a collection, indexed by library name, of collections, indexed by algorithm, of lists of decryptions.
	 * 
	 * @param encryptedData
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a collection of every possible decryption of encryptedData
	 */
	public NameIndexedCollection<NameIndexedCollection<List<ByteDataList>>> decryptWithPassword(byte[] encryptedData, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		HashMap<String, NameIndexedCollection<List<ByteDataList>>> results = new HashMap<String, NameIndexedCollection<List<ByteDataList>>>();
		for(Library passwordLibrary : Library.getPasswordEnabledLibraries()) {
			NameIndexedCollection<List<ByteDataList>> libraryIndexedDecryptions = decryptWithPassword(encryptedData, passwordLibrary, openSSLKeyDerivationMethod);
			results.put(passwordLibrary.name, libraryIndexedDecryptions);
		}
		return new NameIndexedCollection<NameIndexedCollection<List<ByteDataList>>>(results);
	}
	
	/**
	 * @see decryption.Decryptor#decryptWithPassword(byte[], decryption.OpenSSLDecryptor.KeyDerivationMethod)
	 * 
	 * @param encryptedFilename
	 * @param openSSLKeyDerivationMethod if known, and if relevant, the key generation algorithm for OpenSSL; can be null
	 * @return a collection of every possible decryption of the file at encryptedFilename
	 */
	public NameIndexedCollection<NameIndexedCollection<List<ByteDataList>>> decryptWithPassword(String encryptedFilename, OpenSSLDecryptor.KeyDerivationMethod openSSLKeyDerivationMethod) {
		return decryptWithPassword(FileUtilities.readFile(encryptedFilename), openSSLKeyDerivationMethod);
	}
}
