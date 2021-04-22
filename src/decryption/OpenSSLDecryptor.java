package decryption;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;
import org.bouncycastle.jcajce.provider.digest.MD5;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jcajce.provider.digest.MD5.Digest;

import decryption.Constants.AEADAlgorithm;
import decryption.Constants.Algorithm;
import decryption.Constants.BlockAlgorithm;
import decryption.Constants.StreamAlgorithm;
import decryption.parameters.KeyIvParameters;
import utilities.ConsolePrinter;

/**
 * Decryptor specialized in dealing with OpenSSL, a popular command line tool and C library.
 * OpenSSL generates the key and IV from the user supplied password with a random salt, written during encryption before the ciphertext.
 * There are three main methods to generate these parameters, depending on the version of OpenSSL (but it can also be chosen).
 * 
 * @author Francesco Rositano
 */
public class OpenSSLDecryptor {
	/**
	 * SHA256 with iteration count of 1, MD5 with iteration count of 1, PBKDF2 (SHA256) with iteration count of 1000
	 */
	public enum KeyDerivationMethod {
		SHA256,
		MD5,
		PBKDF2 };
	
	/**
	 * Generates all the parameters needed for decryption, based on the password.
	 * This is the interface to OpenSSLDecryptor and takes as input the algorithm,
	 * that is needed to get the right key and IV lengths.
	 * 
	 * @param password user supplied password
	 * @param salt random salt generated on encryption and extracted from the encrypted data
	 * @param algorithm the algorithm to decrypt with
	 * @param keyDerivationMethod the chosen way to derive key and IV
	 * @return a bundle of parameters (key, IV)
	 */
	public static KeyIvParameters generateParametersFromPassword(byte[] password, byte[] salt, Algorithm algorithm, KeyDerivationMethod keyDerivationMethod) {
		ParametersSize paramsSize = getStandardParametersSize(algorithm);
		return generate(password, salt, paramsSize.getKeyLengthBytes(), paramsSize.getIvLengthBytes(), keyDerivationMethod);
	}
	
	public static KeyIvParameters generateParametersFromPassword(String password, byte[] salt, Algorithm algorithm, KeyDerivationMethod keyDerivationMethod) {
		ParametersSize paramsSize = getStandardParametersSize(algorithm);
		return generate(password.getBytes(), salt, paramsSize.getKeyLengthBytes(), paramsSize.getIvLengthBytes(), keyDerivationMethod);
	}
	
	/**
	 * Generates a bundle made of key and IV. It needs to know key and IV length in bytes, so generally this is not called directly;
	 * ({@link decryption.OpenSSLDecryptor#generateParametersFromPassword(byte[], byte[], Algorithm, KeyDerivationMethod)} is preferred because it handles those lengths.
	 * 
	 * @param password
	 * @param salt
	 * @param keyLengthBytes
	 * @param ivLengthBytes
	 * @param keyDerivationMethod
	 * @return {@link decryption.parameters.KeyIvParameters} containing key and IV
	 */
	public static KeyIvParameters generate(byte[] password, byte[] salt, int keyLengthBytes, int ivLengthBytes, KeyDerivationMethod keyDerivationMethod) {
		byte[] keyAndIv = null;
		// select the right function to generate a single array comprising of key and IV
		switch(keyDerivationMethod) {
			case SHA256:
				keyAndIv = generateKeyIvBytes(new SHA256.Digest(), password, salt, keyLengthBytes, ivLengthBytes);
				break;
			case MD5:
				keyAndIv = generateKeyIvBytes(new MD5.Digest(), password, salt, keyLengthBytes, ivLengthBytes);
				break;
			case PBKDF2:
				try {
					keyAndIv = doPbkdf2(new String(password).toCharArray(), salt, 10000, keyLengthBytes + ivLengthBytes);
					// divide keyAndIv into two arrays
					byte[] key = Arrays.copyOfRange(keyAndIv, 0, keyLengthBytes);
					byte[] iv = Arrays.copyOfRange(keyAndIv, key.length, keyAndIv.length);
					return new KeyIvParameters(key, iv);
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				break;
			default:
				keyAndIv = null;
				break;
		}
		// divide keyAndIv into two arrays
		byte[] key = Arrays.copyOfRange(keyAndIv, 0, keyLengthBytes);
		byte[] iv = Arrays.copyOfRange(keyAndIv, key.length, keyAndIv.length);
		return new KeyIvParameters(key, iv);
	}
	
	/**
	 * Generates a single byte array of key and IV in the old OpenSSL way.
	 * 
	 * @param digest the digest function at the core of the process; either SHA256 or MD5
	 * @param password
	 * @param salt
	 * @param keyLengthBytes
	 * @param ivLengthBytes
	 * @return key and IV in a single array
	 */
	private static byte[] generateKeyIvBytes(BCMessageDigest digest, byte[] password, byte[] salt, int keyLengthBytes, int ivLengthBytes) {
		int lengthGoal = keyLengthBytes + ivLengthBytes;
		byte[] passwordAndSalt = concatenate(password, salt);
		byte[] keyAndIv = null;
		byte[] d = null;
		int currentLength = 0;
		while(currentLength < lengthGoal) {
			d = digest.digest(concatenate(d, passwordAndSalt));
			keyAndIv = concatenate(keyAndIv, d);
			currentLength = keyAndIv.length;
		}
		return Arrays.copyOf(keyAndIv, lengthGoal);
	}
	
	/**
	 * Generates a single byte array of key and IV in the new, more secure way.
	 * The PBKDF2 standard suggests to use at least 1000 iterations.
	 * 
	 * @param password
	 * @param salt
	 * @param iterations standard number is 1000
	 * @param generatedLengthBits number of bytes to generate (key length + IV length)
	 * @return key and IV in a single array
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static byte[] doPbkdf2(char[] password, byte[] salt, int iterations, int generatedLengthBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec keySPec = new PBEKeySpec(password, salt, iterations, generatedLengthBytes * 8);
        SecretKeyFactory secretKeyFact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return secretKeyFact.generateSecret(keySPec).getEncoded();
	}
	
	/**
	 * Generates a couple consisting of length of key and length of IV.
	 * 
	 * @param algorithm the algorithm these parameters are used with
	 * @return key length and IV length
	 */
	public static ParametersSize getStandardParametersSize(Algorithm algorithm) {
		if(algorithm instanceof BlockAlgorithm) {
			switch((BlockAlgorithm)algorithm) {
			case AES:
			case CAMELLIA:
				return new ParametersSize(32, 16);
			case BLOWFISH:
				return new ParametersSize(16, 8);
			case IDEA:
				return new ParametersSize(16, 8);
			case DES:
				return new ParametersSize(8, 8);
			case DES3:
				return new ParametersSize(24, 8);
			default:
				return null;
			}
		} else if(algorithm instanceof StreamAlgorithm) {
			switch((StreamAlgorithm)algorithm) {
			case CHACHA20:
				return new ParametersSize(32, 16);
			case RC4:
				return new ParametersSize(16, 0);
			default:
				return null;
			}
		} else if(algorithm instanceof AEADAlgorithm) {
			switch((AEADAlgorithm)algorithm) {
			case AES_AEAD:
				return new ParametersSize(32, 12);
			case CHACHA20POLY1305:
				return new ParametersSize(32, 12);
			default:
				return null;
			}
		} else {
			return null;
		}
	}

	/**
	 * Encapsulates two integers.
	 *
	 */
	public static class ParametersSize{
		private int keyLengthBytes;
		private int ivLengthBytes;
		
		public ParametersSize(int keyLengthBytes, int ivLengthBytes) {
			this.keyLengthBytes = keyLengthBytes;
			this.ivLengthBytes = ivLengthBytes;
		}
		
		public int getKeyLengthBytes() {
			return keyLengthBytes;
		}
		
		public int getKeyLengthBits() {
			return keyLengthBytes * 8;
		}
		
		public int getIvLengthBytes() {
			return ivLengthBytes;
		}
		
		public int getIvLengthBits() {
			return ivLengthBytes * 8;
		}
	}
	
	/**
	 * Simple concatenation function for byte arrays.
	 * 
	 * @param a
	 * @param b
	 * @return a || b; if one is null, it returns a copy of the other
	 */
	private static byte[] concatenate(byte[] a, byte[] b) {
		if(a == null && b != null) {
			return b.clone();
		} else
		if(b == null && a != null) {
			return a.clone();
		} else if( a== null && b == null) {
			return null;
		}
		byte[] ab = new byte[a.length + b.length];
		System.arraycopy(a, 0, ab, 0, a.length);
		System.arraycopy(b, 0, ab, a.length, b.length);
		return ab;
	}
}
