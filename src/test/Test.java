package test;

import java.security.Security;

import decryption.Constants.AEADAlgorithm;
import decryption.Constants.AEADMode;
import decryption.Constants.BlockAlgorithm;
import decryption.Constants.EncryptionMode;
import decryption.Constants.StreamAlgorithm;
import decryption.formats.Library;
import utilities.FileUtilities;

public class Test {

	public static void main(String[] args) {
		
		// Initialization
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Library.init();

		byte[] key256 = FileUtilities.readFile(TestMethods.KEY256);
		byte[] key192 = FileUtilities.readFile(TestMethods.KEY192);
		byte[] key128 = FileUtilities.readFile(TestMethods.KEY128);
		byte[] key64 = FileUtilities.readFile(TestMethods.KEY64);
		byte[] iv128 = FileUtilities.readFile(TestMethods.IV128);
		byte[] iv96 = FileUtilities.readFile(TestMethods.IV96);
		byte[] iv64 = FileUtilities.readFile(TestMethods.IV64);
		
		byte[] additionalData = FileUtilities.readFile(TestMethods.ADDITIONAL_DATA);
		
		byte[] encryptedData = FileUtilities.readFile(TestMethods.OPENSSL_BASE_DIRECTORY + TestMethods.PBKDF2 + TestMethods.BLOWFISH);
		TestMethods.testDecryptorWithPassword(encryptedData, TestMethods.PASSWORD, null, additionalData,
				null, null, null);
		
		//TestMethods.testDecryptorWithKey(encryptedData, key256, iv96, additionalData,
		//		null, null, null);
	}
	
}
