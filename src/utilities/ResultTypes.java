package utilities;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Collection of wrapper classes used by the methods of {@link decryptor.Decryptor}
 * 
 * @author Francesco Rositano
 *
 */
public class ResultTypes {
	/**
	 * Basic wrapper for a list of arrays of bytes.
	 * Used by {@link decryptor.Decryptor} to represent a list of decryptions
	 */
	public static class ByteDataList implements Iterable<byte[]>{
		public List<byte[]> byteData;
		
		public ByteDataList(List<byte[]> byteData) {
			this.byteData = byteData;
		}

		@Override
		public Iterator<byte[]> iterator() {
			return byteData.iterator();
		}
		
		public byte[] get(int index) {
			return byteData.get(index);
		}

		public int size() {
			return byteData.size();
		}
	}
	
	/**
	 * Basic wrapper for a HashMap, whose keys are strings.
	 * Used by {@link decryptor.Decryptor} to represent a list of decryptions indexed by name (library, algorithm...).
	 */
	public static class NameIndexedCollection <T>{
		public HashMap<String, T> table;
		
		public NameIndexedCollection(HashMap<String, T> table) {
			this.table = table;
		}
		
		public T getByName(String name) {
			return table.get(name);
		}
		
		public Set<String> getNames() {
			return table.keySet();
		}
		
		public Collection<T> getValues() {
			return table.values();
		}
	}
}
