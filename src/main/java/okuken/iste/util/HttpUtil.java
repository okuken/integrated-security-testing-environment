package okuken.iste.util;

public class HttpUtil {

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

	private static final byte[] COOKIE_START = "\r\nCookie:".getBytes();
	private static final byte[] COOKIE_END = "\r\n".getBytes();
	private static final byte[] HEADER_END = "\r\n\r\n".getBytes();
	private static int endIndexOfCookie(byte[] request) {
		return ByteUtil.endIndexOf(request, HEADER_END, COOKIE_START, COOKIE_END);
	}

}
