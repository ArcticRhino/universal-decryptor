package utilities;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Utility class for reading and writing to files.
 * 
 * @author Francesco Rositano
 *
 */
public class FileUtilities {

	public static void writeFile(String name, byte[] data) {
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(name);
			fos.write(data);
			fos.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static byte[] readFile(String name) {
		FileInputStream fis;
		try {
			fis = new FileInputStream(name);
			byte[] data = fis.readAllBytes();
			fis.close();
			return data;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
}
