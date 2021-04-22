package decryption.ciphers;

import java.io.IOException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;

import decryption.DefuseDecryptor;
import decryption.Constants.AEADAlgorithm;
import decryption.Constants.Algorithm;
import decryption.Constants.BlockAlgorithm;
import decryption.Constants.EncryptionMode;
import decryption.Constants.Mode;
import decryption.Constants.StreamAlgorithm;
import decryption.OpenSSLDecryptor;
import decryption.PGPDecryptor;
import decryption.formats.DataFormatHelper;
import decryption.formats.FormatDefinition.EncryptionFormat;
import decryption.formats.FormatDefinition.Format;
import decryption.formats.Library;
import decryption.parameters.KeyIvCounterParameters;
import decryption.parameters.KeyIvParameters;

/**
 * A special cipher for decryption using a password.
 * At the moment, used only for decryption with OpenSSL, GnuPG and Defuse.
 * Actually, this is only a common interface for password-based decryption,
 * whose operations are carried out by specialized classes.
 * 
 * @author Francesco Rositano
 * 
 * @see decryption.OpenSSLDecryptor
 * @see decryption.PGPDecryptor
 * @see decryption.DefuseDecryptor
 */
public class PasswordCipher {
	
	protected Algorithm algorithm;
	protected Mode mode;
	protected String password;
	protected OpenSSLDecryptor.KeyDerivationMethod keyDerivationMethod;
	
	public PasswordCipher(Algorithm algorithm, Mode mode, String password) {
		this.algorithm = algorithm;
		this.mode = mode;
		this.password = password;
	}
	
	public PasswordCipher(StreamAlgorithm algorithm, String password) {
		this(algorithm, EncryptionMode.NONE, password);
	}
	
	public PasswordCipher(Algorithm algorithm, Mode mode, String password, OpenSSLDecryptor.KeyDerivationMethod keyDerivationMethod) {
		this(algorithm, mode, password);
		this.keyDerivationMethod = keyDerivationMethod;
	}
	
	public byte[] decrypt(byte[] encryptedData, Format dataFormat) {
		EncryptionFormat encFormat = (EncryptionFormat)dataFormat;
		switch (encFormat) {
			case OPENSSL:
				return decryptOpenssl(encryptedData);
			case GNUPG:
				return decryptGnuPG(encryptedData);
			case DEFUSE_PHP:
				return decryptDefuse(encryptedData);
			default:
				return null;
		}
	}

	private byte[] decryptDefuse(byte[] encryptedData) {
		return DefuseDecryptor.decrypt(encryptedData, password);
	}

	private byte[] decryptGnuPG(byte[] encryptedData) {
		try {
			return PGPDecryptor.decrypt(encryptedData, password.toCharArray());
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Decrypts OpenSSL encrypted data. It delegates the process of recovering key and IV to {@link decryption.OpenSSLDecryptor}.
	 * Authenticated Encryption is not supported by OpenSSL command line tool;
	 * instead, the OpenSSL C API is used in that case and it is most commonly encrypted with a key.
	 * 
	 * @param encryptedData
	 * @return the decryption of encryptedData, or null in case of Authenticated Encryption or failed decryption
	 */
	private byte[] decryptOpenssl(byte[] encryptedData) {
		// get the parameters, based on the password
		byte[] salt = DataFormatHelper.extractSaltEncryptionOpensslPassword(encryptedData);
		if(salt == null) {
			return null;
		}
		KeyIvParameters params = OpenSSLDecryptor.generateParametersFromPassword(password, salt, algorithm, keyDerivationMethod);
		if(params == null) {
			return null;
		}
		byte[] ciphertext = DataFormatHelper.extractCiphertextEncryptionOpensslPassword(encryptedData);
		if(ciphertext == null) {
			return null;
		}
		// actually decrypt with obtained parameters
		if(algorithm instanceof BlockAlgorithm) {
			BlockCipher cipher = new BlockCipher((BlockAlgorithm)algorithm, (EncryptionMode)mode, params);
			return cipher.decrypt(ciphertext, EncryptionFormat.VANILLA);
		} else if (algorithm instanceof StreamAlgorithm) {
			StreamCipher cipher;
			if((StreamAlgorithm)algorithm == StreamAlgorithm.CHACHA20) {
				Library.init();
				KeyIvCounterParameters keyIvCounterParamters = Library.getLibraryByName(Library.LIBRARY_OPENSSL).formatChaChaParametersIfNeeded(params.iv, 0);
				if(keyIvCounterParamters != null) {
					cipher = new StreamCipher((StreamAlgorithm)algorithm, new KeyIvCounterParameters(params.key, keyIvCounterParamters.iv, keyIvCounterParamters.getCounterBytes()));
				} else {
					cipher = new StreamCipher((StreamAlgorithm)algorithm, params);
				}
			}else {
				cipher = new StreamCipher((StreamAlgorithm)algorithm, params);
			}
			return cipher.decrypt(ciphertext, EncryptionFormat.VANILLA);
		} else if(algorithm instanceof AEADAlgorithm) {
			return null;
		}
		return null;
	}
}
