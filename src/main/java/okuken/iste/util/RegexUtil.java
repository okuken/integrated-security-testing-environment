package okuken.iste.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import okuken.iste.consts.Captions;

public class RegexUtil {

	public static boolean judgeHasJustOneGroup(String regex) {
		return Pattern.compile(regex).matcher("").groupCount() == 1;
	}
	public static String judgeHasJustOneGroupAndReturnErrorMsg(String regex) {
		try {
			if(!judgeHasJustOneGroup(regex)) {
				return Captions.MESSAGE_INPUT_INVALID_EXTRACT_REGEX;
			}
		} catch (Exception e) {
			return e.toString();
		}
		return null;
	}

	public static String replaceOneGroup(String str, String regex, String replacement) {
		Matcher matcher = Pattern.compile(regex).matcher(str);
		if(!matcher.find()) {
			return str;
		}
		return new StringBuilder()
			.append(str.substring(0, matcher.start(1)))
			.append(replacement)
			.append(str.substring(matcher.end(1)))
			.toString();
	}

	public static String extractOneGroup(byte[] bytes, String regex) {
		return extractOneGroup(convertToStringForRegex(bytes), regex);
	}
	public static String extractOneGroup(String str, String regex) {
		return extractOneGroup(str, Pattern.compile(regex));
	}
	public static String extractOneGroup(String str, Pattern regexPattern) {
		var matcher = regexPattern.matcher(str);
		if(!matcher.find()) {
			return null;
		}
		return matcher.group(1);
	}

	public static String convertToStringForRegex(byte[] bytes) {
		return new String(bytes, ByteUtil.DEFAULT_SINGLE_BYTE_CHARSET);
	}

}
