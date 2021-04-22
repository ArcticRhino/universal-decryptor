package utilities;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Utility class for conversion between bytes and integers.
 * 
 * @author Francesco Rositano
 *
 */
public class IntBytesConverter {
	public static byte[] intToBytes(int input) {
		return intToBytes(input, 4);
	}
	
	/**
	 * Converts an integer to an array of bytes.
	 * 
	 * @param input the integer to convert
	 * @param bytesNumber length of the resulting array
	 * @return the bytes representing the integer input
	 */
	public static byte[] intToBytes(int input, int bytesNumber) {
		return ByteBuffer.allocate(bytesNumber).putInt(input).array();
	}
	
	/**
	 * Converts an array of bytes to a 32 bits integer.
	 * 
	 * @param input the bytes to convert
	 * @param isBigEndian whether input has to be considered big-endian or not. Default is false
	 * @return the integer represented by the input
	 */
	public static int bytesToInt(byte[] input, boolean isBigEndian) {
		ByteBuffer bb = ByteBuffer.wrap(input);
		if(isBigEndian) {
			bb.order( ByteOrder.BIG_ENDIAN);
		} else {
			bb.order( ByteOrder.LITTLE_ENDIAN);
		}
		
		return bb.getInt();
	}
	
	public static long getUInt32(byte[] input){
		try {
			long value = input[0] & 0xFF;
		    value |= (input[1] << 8) & 0xFFFF;
		    value |= (input[2] << 16) & 0xFFFFFF;
		    value |= (input[3] << 24) & 0xFFFFFFFF;
		    return value;
		} catch(Exception e) {
			return 0;
		}
	    
	}
}
