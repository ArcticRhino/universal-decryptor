package decryption.formats;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.util.Arrays;

import decryption.Constants.AEADAlgorithm;
import decryption.Constants.AEADMode;
import decryption.Constants.Algorithm;
import decryption.Constants.BlockAlgorithm;
import decryption.Constants.EncryptionMode;
import decryption.Constants.Mode;
import decryption.Constants.StreamAlgorithm;
import decryption.formats.FormatDefinition.AEADFormat;
import decryption.formats.FormatDefinition.EncryptionFormat;
import decryption.parameters.KeyIvCounterParameters;
import decryption.parameters.KeyIvParameters;
import utilities.ConsolePrinter;
import utilities.IntBytesConverter;

/**
 * This class collects all the characteristics specific to each supported library,
 * as such as which algorithms it can encrypt with and information on how to treat inputs.
 * Each library is identified by its name.
 * <p>
 * In order to take advantage of libraries, one must call {@link decryption.formats.Library#init()} before anything else.
 * Libraries can be added with {@link decryption.formats.Library#addLibrary(String, Library)} to be used for decryption.
 * 
 * @author Francesco Rositano
 *
 */
public class Library {
	// Constants
	public static final String LIBRARY_OPENSSL = "openssl";
	public static final String LIBRARY_GNUPG = "gnupg";
	public static final String LIBRARY_BOUNCY_CASTLE = "bouncy";
	public static final String LIBRARY_TINK = "tink";
	public static final String LIBRARY_JAVA_SUN_PROVIDER = "sunjce";
	public static final String LIBRARY_PYTHON_CRYPTOGRAPHY = "python-cryptography";
	public static final String LIBRARY_PYCRYPTO = "pycrypto";
	public static final String LIBRARY_CSHARPCRYPTOGRAPHY = "csharp-cryptography";
	public static final String LIBRARY_CRYPTOPP = "cryptopp";
	public static final String LIBRARY_BOTAN = "botan";
	public static final String LIBRARY_NETTLE = "nettle";
	public static final String LIBRARY_WOLFCRYPT = "wolfcrypt";
	public static final String LIBRARY_LIBTOMCRYPT = "libtomcrypt";
	public static final String LIBRARY_LIBGCRYPT = "libgcrypt";
	public static final String LIBRARY_DEFUSE = "defuse";

	public static final BlockAlgorithm[] allBlockAlgorithms = new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.CAMELLIA,
			BlockAlgorithm.DES, BlockAlgorithm.DES3, BlockAlgorithm.SERPENT, BlockAlgorithm.BLOWFISH, BlockAlgorithm.IDEA, BlockAlgorithm.TWOFISH};
	public static final StreamAlgorithm[] allStreamAlgorithms = new StreamAlgorithm[] {StreamAlgorithm.CHACHA20, StreamAlgorithm.RC4};
	public static final AEADAlgorithm[] allAEADAlgorithms = new AEADAlgorithm[] {AEADAlgorithm.AES_AEAD, AEADAlgorithm.CHACHA20POLY1305};
	public static final EncryptionMode[] allEncryptionModes = new EncryptionMode[] {EncryptionMode.NONE, EncryptionMode.CBC, EncryptionMode.CFB, EncryptionMode.CTR,
			EncryptionMode.ECB, EncryptionMode.OFB};
	public static final AEADMode[] allAEADModes = new AEADMode[] {AEADMode.NONE, AEADMode.CCM, AEADMode.EAX, AEADMode.GCM};
	
	public static final BlockAlgorithm[] noBlockAlgorithms = new BlockAlgorithm[] {BlockAlgorithm.NONE};
	public static final StreamAlgorithm[] noStreamAlgorithms = new StreamAlgorithm[] {StreamAlgorithm.NONE};
	public static final AEADAlgorithm[] noAEADAlgorithms = new AEADAlgorithm[] {AEADAlgorithm.NONE};
	public static final EncryptionMode[] noEncryptionModes = new EncryptionMode[] {EncryptionMode.NONE};
	public static final AEADMode[] noAEADModes = new AEADMode[] {AEADMode.NONE};
	
	/**
	 * Collection of supported libraries, indexed by name.
	 */
	public static HashMap<String, Library> libraries;
	
	public String name;
	public EncryptionFormat encryptionFormat;
	public AEADFormat aeadFormat;
	
	public BlockAlgorithm[] blockAlgorithms;
	public StreamAlgorithm[] streamAlgorithms;
	public AEADAlgorithm[] aeadAlgorithms;
	
	public EncryptionMode[] encryptionModes;
	public AEADMode[] aeadmodes;
	
	public boolean supportsPassword;
	
	private int defaultChachaCounter;
	private int defaultTagLengthBytes;

	// Interfaces
	private ChaChaParametersFormatter chaChaParametersFormatter;
	private CtrParametersFormatter ctrParametersFormatter;


	public Library(String name, EncryptionFormat encryptionFormat, AEADFormat aeadFormat, BlockAlgorithm[] blockAlgorithms, EncryptionMode[] encryptionModes, StreamAlgorithm[] streamAlgorithms, AEADAlgorithm[] aeadAlgorithms, AEADMode[] aeadmodes, boolean supportsPassword, int defaultChachaCounter, int defaultTagLengthBytes) {
		this(name, encryptionFormat, aeadFormat, blockAlgorithms, encryptionModes, streamAlgorithms, aeadAlgorithms, aeadmodes, supportsPassword, defaultChachaCounter, defaultTagLengthBytes, null, null);
	}
	
	public Library(String name, EncryptionFormat encryptionFormat, AEADFormat aeadFormat, BlockAlgorithm[] blockAlgorithms, EncryptionMode[] encryptionModes, StreamAlgorithm[] streamAlgorithms, AEADAlgorithm[] aeadAlgorithms, AEADMode[] aeadmodes, boolean supportsPassword, int defaultChachaCounter, int defaultTagLengthBytes, ChaChaParametersFormatter chaChaParametersFormatter) {
		this(name, encryptionFormat, aeadFormat, blockAlgorithms, encryptionModes, streamAlgorithms, aeadAlgorithms, aeadmodes, supportsPassword, defaultChachaCounter, defaultTagLengthBytes, chaChaParametersFormatter, null);
	}
	
	public Library(String name, EncryptionFormat encryptionFormat, AEADFormat aeadFormat, BlockAlgorithm[] blockAlgorithms, EncryptionMode[] encryptionModes, StreamAlgorithm[] streamAlgorithms, AEADAlgorithm[] aeadAlgorithms, AEADMode[] aeadmodes, boolean supportsPassword, int defaultChachaCounter, int defaultTagLengthBytes, CtrParametersFormatter ctrParametersFormatter) {
		this(name, encryptionFormat, aeadFormat, blockAlgorithms, encryptionModes, streamAlgorithms, aeadAlgorithms, aeadmodes, supportsPassword, defaultChachaCounter, defaultTagLengthBytes, null, ctrParametersFormatter);
	}
	
	public Library(String name, EncryptionFormat encryptionFormat, AEADFormat aeadFormat, BlockAlgorithm[] blockAlgorithms, EncryptionMode[] encryptionModes, StreamAlgorithm[] streamAlgorithms, AEADAlgorithm[] aeadAlgorithms, AEADMode[] aeadmodes, boolean supportsPassword, int defaultChachaCounter, int defaultTagLengthBytes, ChaChaParametersFormatter chaChaParametersFormatter, CtrParametersFormatter ctrParametersFormatter) {
		this.name = name;
		this.encryptionFormat = encryptionFormat;
		this.aeadFormat = aeadFormat;
		this.blockAlgorithms = blockAlgorithms;
		this.aeadAlgorithms = aeadAlgorithms;
		this.streamAlgorithms = streamAlgorithms;
		this.encryptionModes = encryptionModes;
		this.aeadmodes = aeadmodes;
		this.supportsPassword = supportsPassword;
		this.defaultChachaCounter = defaultChachaCounter;
		this.defaultTagLengthBytes = defaultTagLengthBytes;
		this.chaChaParametersFormatter = chaChaParametersFormatter;
		this.ctrParametersFormatter = ctrParametersFormatter;
	}

	public boolean supportsAlgorithm(Algorithm algorithm) {
		if(algorithm instanceof BlockAlgorithm) {
			for(Algorithm supportedAlgorithm : blockAlgorithms) {
				if(algorithm == supportedAlgorithm)
					return true;
			}
		} else if(algorithm instanceof StreamAlgorithm) {
			for(Algorithm supportedAlgorithm : streamAlgorithms) {
				if(algorithm == supportedAlgorithm)
					return true;
			}
		} else if(algorithm instanceof AEADAlgorithm) {
			for(Algorithm supportedAlgorithm : aeadAlgorithms) {
				if(algorithm == supportedAlgorithm)
					return true;
			}
		}
		return false;
	}
	
	public boolean supportsMode(Mode mode) {
		if(mode instanceof EncryptionMode) {
			for(Mode supportedMode : encryptionModes) {
				if(mode == supportedMode)
					return true;
			}
		} else if(mode instanceof AEADMode) {
			for(Mode supportedMode : aeadmodes) {
				if(mode == supportedMode)
					return true;
			}
		}
		return false;
	}
	
	/**
	 * Even though, in general, libraries require a key for encryption, some of them accept a password
	 * as input (like command line based libraries such as OpenSSL).
	 * 
	 * @return a list of libraries that may accept a password instead of a key
	 */
	public static ArrayList<Library> getPasswordEnabledLibraries() {
		ArrayList<Library> passwordEnabledLibraries = new ArrayList<Library>();
		Iterator<Entry<String, Library>> it = libraries.entrySet().iterator();
	    while (it.hasNext()) {
	        Map.Entry<String, Library> pair = (Map.Entry<String, Library>)it.next();
	        Library library = (Library) pair.getValue();
	        if(library.supportsPassword)
	        	passwordEnabledLibraries.add(library);
	        it.remove();
	    }
	    return passwordEnabledLibraries;
	}
	
	public static Library getLibraryByName(String name) {
		return libraries.get(name);
	}
	
	/**
	 * Returns if the encryption generated by this library stores the IV along with the ciphertext.
	 * 
	 * @param standardEncryption whether you are interested in Standard Encryption (Block, Stream) or Authenticated Encryption
	 * @return true if the format adopted by this library contains an IV
	 */
	public boolean formatContainsIv(boolean standardEncryption) {
		if(standardEncryption) {
			return encryptionFormat.containsIv();
		} else {
			return aeadFormat.containsIv();
		}
	}
	
	/**
	 * Returns if the encryption generated by this library stores the tag along with the ciphertext, in the case of Authenticated Encryption.
	 * 
	 * @return true if the format adopted by this library contains a tag
	 */
	public boolean formatContainsTag() {
		return aeadFormat.containsTag();
	}
	
	/**
	 * Allows the user to add a library to decrypt with.
	 * 
	 * @param name name of the new library
	 * @param library the new library to add
	 */
	public static void addLibrary(String name, Library library) {
		if(libraries == null) {
			init();
		}
		libraries.put(name, library);
	}

	/**
	* Initializes the libraries that are currently supported.
	* This method has to be called before using {@link decryption.Decryptor}
	* and, in general, before using these libraries.
	*/
	public static void init() {
		libraries = new HashMap<String, Library>();
		// CLI
		libraries.put(LIBRARY_OPENSSL, new Library(LIBRARY_OPENSSL, EncryptionFormat.OPENSSL, AEADFormat.SEPARATED,
				new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.CAMELLIA, BlockAlgorithm.BLOWFISH, BlockAlgorithm.IDEA, BlockAlgorithm.DES, BlockAlgorithm.DES3},
				allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, true, 0, 16,
				new ChaChaParametersFormatter() {
					private final int REQUIRED_NONCE_LENGTH = 16;
					
					// OpenSSL extends the IV with zeroes if too short
					@Override
					public KeyIvCounterParameters format(byte[] nonce, int counter) {
						byte[] resultNonce = null;
						if(nonce.length < REQUIRED_NONCE_LENGTH) {
							resultNonce = new byte[REQUIRED_NONCE_LENGTH];
							for(int i = 0; i < REQUIRED_NONCE_LENGTH; i++) {
								resultNonce[i] = 0x00;
							}
							System.arraycopy(nonce, 0, resultNonce, 0, nonce.length);
						} else if(nonce.length > REQUIRED_NONCE_LENGTH) {
							resultNonce = new byte[REQUIRED_NONCE_LENGTH];
							System.arraycopy(nonce, 0, resultNonce, 0, REQUIRED_NONCE_LENGTH);
						} else {
							resultNonce = nonce;
						}
						int resultCounter = IntBytesConverter.bytesToInt(Arrays.copyOfRange(resultNonce, 0, 4), false);
						ConsolePrinter.printMessage("new counter: " +  resultCounter);
						resultNonce = Arrays.copyOfRange(resultNonce, 4, resultNonce.length);
						return new KeyIvCounterParameters(null, resultNonce, resultCounter);
					}
				}));
		libraries.put(LIBRARY_GNUPG, new Library(LIBRARY_GNUPG, EncryptionFormat.GNUPG, AEADFormat.GNUPG,
						new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.CAMELLIA, BlockAlgorithm.BLOWFISH, BlockAlgorithm.TWOFISH, BlockAlgorithm.DES3},
						allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, new AEADMode[] {AEADMode.GCM, AEADMode.CCM}, true, 0, 16));
				
		// Java
		libraries.put(LIBRARY_BOUNCY_CASTLE, new Library(LIBRARY_BOUNCY_CASTLE, EncryptionFormat.VANILLA, AEADFormat.CIPHERTEXT_TAG,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16));
		libraries.put(LIBRARY_TINK, new Library(LIBRARY_TINK, EncryptionFormat.NONE, AEADFormat.IV_CIPHERTEXT_TAG,
				noBlockAlgorithms, noEncryptionModes, noStreamAlgorithms, allAEADAlgorithms, new AEADMode[] {AEADMode.EAX, AEADMode.GCM}, false, 0, 16));
		libraries.put(LIBRARY_JAVA_SUN_PROVIDER, new Library(LIBRARY_JAVA_SUN_PROVIDER, EncryptionFormat.VANILLA, AEADFormat.NONE,
				new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.BLOWFISH, BlockAlgorithm.DES, BlockAlgorithm.DES3},
				new EncryptionMode[] {EncryptionMode.CBC, EncryptionMode.CTR}, new StreamAlgorithm[] {StreamAlgorithm.RC4}, noAEADAlgorithms, noAEADModes, false, 0, 16));
		
		// Python
		
		libraries.put(LIBRARY_PYTHON_CRYPTOGRAPHY, new Library(LIBRARY_PYTHON_CRYPTOGRAPHY, EncryptionFormat.VANILLA, AEADFormat.CIPHERTEXT_TAG,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16, new ChaChaParametersFormatter() {
					private final int REQUIRED_NONCE_LENGTH = 16;
					// ChaCha IV of 16 bytes: 8 counter + 8 nonce
					@Override
					public KeyIvCounterParameters format(byte[] nonce128Bits, int counter) {
						if(nonce128Bits.length == REQUIRED_NONCE_LENGTH) {
							byte[] counterBytes = Arrays.copyOfRange(nonce128Bits, 0, 4);
							int resultCounter = IntBytesConverter.bytesToInt(counterBytes, false);
							byte[] resultNonce96Bits = Arrays.copyOfRange(nonce128Bits, 4, nonce128Bits.length);
							return new KeyIvCounterParameters(null, resultNonce96Bits, resultCounter);
						} else {
							return new KeyIvCounterParameters(null, nonce128Bits, counter);
						}
					}
				}));
		libraries.put(LIBRARY_PYCRYPTO, new Library(LIBRARY_PYCRYPTO, EncryptionFormat.VANILLA, AEADFormat.SEPARATED,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16, new CtrParametersFormatter() {
					
					// PyCrypto allows the user to specify a 8 byte long IV, although the standard length is 16 bytes.
					// The new IV is the concatenation of iv and counter
					@Override
					public KeyIvParameters format(byte[] iv, int counterValue, byte[] counterBytes) {
						if(iv.length == 16) {
							return new KeyIvParameters(null, iv);
						} else if(iv.length == 8) {
							byte[] ivAndCounter = new byte[16];
							System.arraycopy(iv, 0, ivAndCounter, 0, iv.length);
							if(counterValue >= 0) {
								byte[] convertedCounterBytes = IntBytesConverter.intToBytes(counterValue, 8);
								System.arraycopy(convertedCounterBytes, 0, ivAndCounter, iv.length, convertedCounterBytes.length);
							} else if(counterBytes != null) {
								System.arraycopy(counterBytes, 0, ivAndCounter, iv.length, 8);
							} else {
								ivAndCounter = iv;
							}
							return new KeyIvParameters(null, ivAndCounter);
						}
						return null;
					}
				}));
		
		// C#
		libraries.put(LIBRARY_CSHARPCRYPTOGRAPHY, new Library(LIBRARY_CSHARPCRYPTOGRAPHY, EncryptionFormat.VANILLA, AEADFormat.SEPARATED,
				new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.DES, BlockAlgorithm.DES3},
				allEncryptionModes, noStreamAlgorithms, noAEADAlgorithms, noAEADModes, false, 0, 16));
		
		// C++
		libraries.put(LIBRARY_CRYPTOPP, new Library(LIBRARY_CRYPTOPP, EncryptionFormat.VANILLA, AEADFormat.CIPHERTEXT_TAG,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 12));
		libraries.put(LIBRARY_BOTAN, new Library(LIBRARY_BOTAN, EncryptionFormat.VANILLA, AEADFormat.CIPHERTEXT_TAG,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 1, 16));
		
		// C
		// EAX is restricted to AES-128
		libraries.put(LIBRARY_NETTLE, new Library(LIBRARY_NETTLE, EncryptionFormat.VANILLA, AEADFormat.SEPARATED,
				new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.CAMELLIA, BlockAlgorithm.DES, BlockAlgorithm.DES3},
				allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16));
		libraries.put(LIBRARY_WOLFCRYPT, new Library(LIBRARY_WOLFCRYPT, EncryptionFormat.VANILLA, AEADFormat.SEPARATED,
				new BlockAlgorithm[] {BlockAlgorithm.AES, BlockAlgorithm.CAMELLIA, BlockAlgorithm.DES3}, allEncryptionModes,
				allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16));
		libraries.put(LIBRARY_LIBTOMCRYPT, new Library(LIBRARY_LIBTOMCRYPT, EncryptionFormat.VANILLA, AEADFormat.SEPARATED,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16));
		libraries.put(LIBRARY_LIBGCRYPT, new Library(LIBRARY_LIBGCRYPT, EncryptionFormat.VANILLA, AEADFormat.SEPARATED,
				allBlockAlgorithms, allEncryptionModes, allStreamAlgorithms, allAEADAlgorithms, allAEADModes, false, 0, 16));
		
		// PHP
		libraries.put(LIBRARY_DEFUSE, new Library(LIBRARY_DEFUSE, EncryptionFormat.DEFUSE_PHP, AEADFormat.NONE,
				new BlockAlgorithm[] {BlockAlgorithm.AES}, new EncryptionMode[] {EncryptionMode.CTR}, noStreamAlgorithms, noAEADAlgorithms, noAEADModes, true, 0, 16));
	}
	
	public int getDefaultTagLengthBytes() {
		return defaultTagLengthBytes;
	}
	
	public KeyIvCounterParameters formatChaChaParametersIfNeeded(byte[] nonce, int counter) {
		if (chaChaParametersFormatter != null) {
			return chaChaParametersFormatter.format(nonce, counter);
		} else {
			return null;
		}
	}
	
	public KeyIvParameters formatCTRParametersIfNeeded(byte[] iv, int counter, byte[] counterBytes) {
		if (ctrParametersFormatter != null) {
			return ctrParametersFormatter.format(iv, counter, counterBytes);
		} else {
			return null;
		}
	}
	
	/*
	 * INTERFACES
	 */
	public interface ChaChaParametersFormatter{
		public KeyIvCounterParameters format(byte[] nonce, int counter);
	}
	
	public interface CtrParametersFormatter{
		public KeyIvParameters format(byte[] iv, int counterValue, byte[] counterBytes);
	}
	
}
