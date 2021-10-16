package okuken.iste.util;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

public class ArrayUtil {

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static List toList(Object array) {
		if(array == null) {
			return null;
		}

		var ret = new ArrayList();
		for(int i = 0; i < Array.getLength(array); i++) {
			ret.add(Array.get(array, i));
		}
		return ret;
	}

}
