package okuken.iste.util;

import okuken.iste.client.BurpApiClient;
import okuken.iste.enums.EncodeType;

public class EncodeUtil {

	public static String encode(String value, EncodeType encode) {
		if(value == null) {
			return null;
		}

		switch (encode) {
		case URL:
			return BurpApiClient.i().urlEncode(value);
		default:
			return value;
		}
	}

}
