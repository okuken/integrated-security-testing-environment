package okuken.iste.util;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HttpUtil {

	public static final Charset DEFAULT_HTTP_HEADER_CHARSET = StandardCharsets.US_ASCII;

	public static byte[] removeDustAtEndOfCookieHeader(byte[] request) {
		var endIndexOfCookie = HttpUtil.endIndexOfCookie(request);
		if(endIndexOfCookie > 0) {
			if(request[endIndexOfCookie] == ';') {
				return ByteUtil.remove(request, endIndexOfCookie);
			}
			if(request[endIndexOfCookie] == ' ' && endIndexOfCookie - 1 > 0 && request[endIndexOfCookie - 1] == ';') {
				var ret = ByteUtil.remove(request, endIndexOfCookie);
				return ByteUtil.remove(ret, endIndexOfCookie - 1);
			}
		}
		return request;
	}

	private static final byte[] COOKIE_START = "\r\nCookie:".getBytes(DEFAULT_HTTP_HEADER_CHARSET);
	private static final byte[] COOKIE_END = "\r\n".getBytes(DEFAULT_HTTP_HEADER_CHARSET);
	private static final byte[] HEADER_END = "\r\n\r\n".getBytes(DEFAULT_HTTP_HEADER_CHARSET);
	private static int endIndexOfCookie(byte[] request) {
		return ByteUtil.endIndexOf(request, HEADER_END, COOKIE_START, COOKIE_END);
	}


	public static byte[] extractMessageBody(byte[] message, int bodyOffset) {
		return Arrays.copyOfRange(message, bodyOffset, message.length);
	}

	private static final String AUTHORIZATION_BEARER_HEADER_PREFIX = "Authorization: Bearer ";
	public static String createAuthorizationBearerHeader(String token) {
		return AUTHORIZATION_BEARER_HEADER_PREFIX + token;
	}
	public static boolean judgeIsAuthorizationBearerHeader(String header) {
		return header.startsWith(AUTHORIZATION_BEARER_HEADER_PREFIX);
	}

}
