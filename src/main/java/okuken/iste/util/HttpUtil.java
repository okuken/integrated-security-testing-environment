package okuken.iste.util;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

public class HttpUtil {

	public static final String HTTP_LINE_SEPARATOR = "\r\n";
	public static final String HTTP_HEADER_BODY_SEPARATOR = "\r\n\r\n";
	public static final Charset DEFAULT_HTTP_HEADER_CHARSET = StandardCharsets.ISO_8859_1;
	public static final Charset DEFAULT_HTTP_BODY_CHARSET = StandardCharsets.ISO_8859_1;

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


	private static final Pattern CONTENT_TYPE_MULTIPART_BOUNDARY_PATTERN = Pattern.compile(";boundary=([^;\r]+)", Pattern.CASE_INSENSITIVE);
	public static String extractContentTypeMultipartBoundary(List<String> headers) {
		return extractHeaderParamValue(headers, "Content-Type:multipart/", ";boundary=", CONTENT_TYPE_MULTIPART_BOUNDARY_PATTERN);
	}

	private static final Pattern CONTENT_TYPE_TEXT_CHARSET_PATTERN = Pattern.compile(";charset=([^;\r]+)", Pattern.CASE_INSENSITIVE);
	public static Charset extractContentTypeTextCharset(List<String> headers) {
		String charsetStr = extractHeaderParamValue(headers, "Content-Type:", ";charset=", CONTENT_TYPE_TEXT_CHARSET_PATTERN);
		if(charsetStr == null) {
			return null;
		}
		return Charset.forName(charsetStr);
	}

	private static String extractHeaderParamValue(List<String> headers, String startsWith, String contains, Pattern paramValueExtractPattern) {
		var targetHeaders = headers.stream()
				.map(header -> header.replaceAll("[ \t\"]", ""))
				.filter(header -> {
					var upperHeader = header.toUpperCase();
					return upperHeader.startsWith(startsWith.toUpperCase())
						&& upperHeader.contains(contains.toUpperCase());
				})
				.collect(Collectors.toList());

		if(targetHeaders.isEmpty()) {
			return null;
		}
		var targetHeader = targetHeaders.get(targetHeaders.size() - 1);

		return RegexUtil.extractOneGroup(targetHeader, paramValueExtractPattern);
	}

	private static byte[] extractMessageHeader(byte[] message, int bodyOffset) {
		return Arrays.copyOfRange(message, 0, bodyOffset - HTTP_HEADER_BODY_SEPARATOR.length());
	}

	public static byte[] extractMessageBody(byte[] message, int bodyOffset) {
		return Arrays.copyOfRange(message, bodyOffset, message.length);
	}

	public static String convertMessageBytesToString(byte[] message, List<String> headers, int bodyOffset) {
		var boundaryBase = extractContentTypeMultipartBoundary(headers);
		if(boundaryBase == null) { // case: singlepart
			return convertMessagePartBytesToString(message, headers, bodyOffset);
		}

		var boundary = createBoundary(boundaryBase, false);
		var boundaryEnd = createBoundary(boundaryBase, true);

		var bodySingleByteStr = new String(extractMessageBody(message, bodyOffset), DEFAULT_HTTP_BODY_CHARSET);
		if(!bodySingleByteStr.startsWith(boundary) || !bodySingleByteStr.endsWith(boundaryEnd)) {
			throw new IllegalArgumentException("message body must start with " + boundary + " and end with " + boundaryEnd);
		}

		var bodySingleByteStrWithoutHeaderFooter = bodySingleByteStr.substring(boundary.length(), bodySingleByteStr.length() - boundaryEnd.length());
		var bodyStrWithoutHeaderFooter = Arrays.stream(StringUtils.splitByWholeSeparator(bodySingleByteStrWithoutHeaderFooter, boundary)).map(part -> {
				var partHeaderEndIndex = part.indexOf(HTTP_HEADER_BODY_SEPARATOR);
				var partBodyOffset = partHeaderEndIndex + HTTP_HEADER_BODY_SEPARATOR.length();
				var partHeaders = Arrays.asList(part.substring(0, partHeaderEndIndex).split(HTTP_LINE_SEPARATOR));
				var partBytes = part.getBytes(DEFAULT_HTTP_BODY_CHARSET);
				return convertMessageBytesToString(partBytes, partHeaders, partBodyOffset); //recursive
			})
			.collect(Collectors.joining(boundary));

		return new StringBuilder()
				.append(new String(extractMessageHeader(message, bodyOffset), DEFAULT_HTTP_HEADER_CHARSET))
				.append(HTTP_HEADER_BODY_SEPARATOR)
				.append(boundary)
				.append(bodyStrWithoutHeaderFooter)
				.append(boundaryEnd)
				.toString();
	}
	private static String convertMessagePartBytesToString(byte[] message, List<String> headers, int bodyOffset) {
		var bodyCharset = detectBodyEncoding(message, headers, bodyOffset);
		return new StringBuilder()
				.append(new String(extractMessageHeader(message, bodyOffset), DEFAULT_HTTP_HEADER_CHARSET))
				.append(HTTP_HEADER_BODY_SEPARATOR)
				.append(new String(extractMessageBody(message, bodyOffset), bodyCharset))
				.toString();
	}
	private static Charset detectBodyEncoding(byte[] message, List<String> headers, int bodyOffset) {
		var charset = extractContentTypeTextCharset(headers);
		if(charset != null) {
			return charset;
		}

		charset = ByteUtil.detectEncoding(extractMessageBody(message, bodyOffset));
		if(charset != null) {
			return charset;
		}

		return DEFAULT_HTTP_BODY_CHARSET;
	}
	private static String createBoundary(String boundaryBase, boolean end) {
		var ret = new StringBuilder().append("--").append(boundaryBase);
		if(end) {
			ret.append("--");
		}
		ret.append(HTTP_LINE_SEPARATOR);

		return ret.toString();
	}

	private static final String AUTHORIZATION_BEARER_HEADER_PREFIX = "Authorization: Bearer ";
	public static String createAuthorizationBearerHeader(String token) {
		return AUTHORIZATION_BEARER_HEADER_PREFIX + token;
	}
	public static boolean judgeIsAuthorizationBearerHeader(String header) {
		return header.startsWith(AUTHORIZATION_BEARER_HEADER_PREFIX);
	}

}
