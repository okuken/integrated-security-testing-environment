package okuken.iste.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexUtil {

	public static boolean judgeHasJustOneGroup(String regex) {
		return Pattern.compile(regex).matcher("").groupCount() == 1;
	}
	public static String judgeHasJustOneGroupAndReturnErrorMsg(String regex) {
		try {
			if(!judgeHasJustOneGroup(regex)) {
				return "Regex must include just one group.\n e.g. hoge=([^&]+)&";
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

	public static String extractOneGroup(String str, String regex) {
		var matcher = Pattern.compile(regex).matcher(str);
		if(!matcher.find()) {
			return null;
		}
		return matcher.group(1);
	}

}
