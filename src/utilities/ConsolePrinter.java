package utilities;

/**
 * Utility class for printing info on the console.
 * 
 * @author Francesco Rositano
 *
 */
public class ConsolePrinter {
	public static void printMessage(String message) {
		System.out.println(message);
	}
	
	/**
	 * Prints a byte array in hexadecimals, divided in rows of rowLength bytes
	 * 
	 * @param bytes the bytes to print
	 * @param rowLength the number of bytes to print in a row
	 */
	public static void printBytes(byte[] bytes, int rowLength) {
	    StringBuilder sb = new StringBuilder();
	    for(int i = 0; i < bytes.length; i++) {
	    	if(i != 0 && i % rowLength == 0) {
	        	sb.append("\n");
	        }
	    	sb.append(String.format("%02X ", bytes[i]));
	    }
	    System.out.println(sb.toString());
	}
	
	public static void printBytes(byte[] bytes) {
	    StringBuilder sb = new StringBuilder();
	    for(int i = 0; i < bytes.length; i++) {
	        sb.append(String.format("%02X ", bytes[i]));
	    }
	    System.out.println(sb.toString());
	}
}
