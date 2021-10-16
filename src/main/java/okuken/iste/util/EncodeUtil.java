package okuken.iste.util;

import okuken.iste.enums.EncodeType;

public class EncodeUtil {

	public static String encode(String value, EncodeType encode) {
		if(value == null) {
			return null;
		}

		switch (encode) {
		case URL:
			return BurpUtil.getHelpers().urlEncode(value);
		default:
			return value;
		}
	}

}
