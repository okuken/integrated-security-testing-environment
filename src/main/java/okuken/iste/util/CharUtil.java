package okuken.iste.util;

public class CharUtil {

	private static final int ASCII_RANGE_DISPLAYABLE_MIN = 0x20;
	private static final int ASCII_RANGE_DISPLAYABLE_MAX = 0x7e;

	public static String getDisplayableRepresentation(int c) {
		if(ASCII_RANGE_DISPLAYABLE_MIN <= c && c <= ASCII_RANGE_DISPLAYABLE_MAX) {
			return String.valueOf((char)c);
		}
		return String.format("[%02X]", c);
	}

}
