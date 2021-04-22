package decryption;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

/**
 * Decryptor specialized in dealing with GnuPG, a popular command line tool, and, more in general, with the PGP format.
 * GnuPG writes a lot of metadata along with the ciphertext (for example, it writes the algorithm used in encryption).
 * Fortunately, Bouncy Castle has a set of classes suitable for parsing PGP formatted data.
 * 
 * @author Francesco Rositano
 */
public class PGPDecryptor {
	
	public static byte[] decrypt(byte[] input, char[] passPhrase) throws IOException, NoSuchProviderException, PGPException {
        InputStream in = new BufferedInputStream(new ByteArrayInputStream(input));
        byte[] decrypted = decryptFile(in, passPhrase);
        in.close();
        return decrypted;
	}
	
	public static byte[] decryptFile(String inputFileName, char[] passPhrase) throws IOException, NoSuchProviderException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        byte[] decrypted = decryptFile(in, passPhrase);
        in.close();
        return decrypted;
	}

	/**
	 * Decrypts a PGP formatted file.
	 * 
	 * @param in input stream on the encrypted data
	 * @param passPhrase the password used for encryption
	 * @return decryption of data supplied by in
	 * @throws IOException when some parts of encrypted data are missing
	 * @throws NoSuchProviderException Bouncy Castle provider for JCE is not found
	 * @throws PGPException
	 */
	public static byte[] decryptFile(InputStream in, char[] passPhrase) throws IOException, NoSuchProviderException, PGPException {
		try {

			in = PGPUtil.getDecoderStream(in);
	        
	        JcaPGPObjectFactory pgpFactory = new JcaPGPObjectFactory(in);
	        PGPEncryptedDataList encryptedDataList;
	        Object pgpObject = pgpFactory.nextObject();
	        
	        if (pgpObject instanceof PGPEncryptedDataList) {
	        	encryptedDataList = (PGPEncryptedDataList)pgpObject;
	        }
	        else {
	        	encryptedDataList = (PGPEncryptedDataList)pgpFactory.nextObject();
	        }

	        PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)encryptedDataList.get(0);

	        InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC")
	        		.build()).setProvider("BC").build(passPhrase));
	        
	        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

	        pgpObject = pgpFact.nextObject();
	        // PGP can compress data upon encryption, so we need to check if this is the case
	        if (pgpObject instanceof PGPCompressedData) {
	            PGPCompressedData   cData = (PGPCompressedData)pgpObject;

	            pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

	            pgpObject = pgpFact.nextObject();
	        }
	        
	        PGPLiteralData literalData = (PGPLiteralData)pgpObject;
	        InputStream literalDataInputStream = literalData.getInputStream();

	        // Actual decryption
	        ByteArrayOutputStream decryptedOutputStream = (new ByteArrayOutputStream());
	        Streams.pipeAll(literalDataInputStream, decryptedOutputStream);
	        
	        byte[] decrypted = decryptedOutputStream.toByteArray();
	        decryptedOutputStream.close();
	        return decrypted;
		} catch(NullPointerException e) {
			return null;
		}
        
    }
}
