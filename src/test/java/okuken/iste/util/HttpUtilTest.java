package okuken.iste.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.Test;

import com.google.common.collect.Lists;

class HttpUtilTest {

	@Test
	void removeDustAtEndOfCookieHeader_position_head() {
		var request = "GET /login/index.php HTTP/1.1\r\nCookie:hoge=fuga;\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nCookie:hoge=fuga\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}
	@Test
	void removeDustAtEndOfCookieHeader_position_middle() {
		var request = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie:hoge=fuga;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie:hoge=fuga\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}
	@Test
	void removeDustAtEndOfCookieHeader_position_tail() {
		var request = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nCookie:hoge=fuga;\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nCookie:hoge=fuga\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}
	@Test
	void removeDustAtEndOfCookieHeader_count_multiple() {
		var request = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie:hoge=fuga; piyo=piyo;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie:hoge=fuga; piyo=piyo\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}
	@Test
	void removeDustAtEndOfCookieHeader_break_cookieHeaderExist() {
		var request = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie:hoge=fuga; piyo=piyo;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\nXXXX\r\nCookie:hoge=fuga;\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie:hoge=fuga; piyo=piyo\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\nXXXX\r\nCookie:hoge=fuga;\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}
	@Test
	void removeDustAtEndOfCookieHeader_break_cookieHeaderNotExist() {
		var request = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\nXXXX\r\nCookie:hoge=fuga;\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\nXXXX\r\nCookie:hoge=fuga;\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}
	@Test
	void removeDustAtEndOfCookieHeader_break_breakerNotExist() {
		var request = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n".getBytes(StandardCharsets.US_ASCII);
		var expect  = "GET /login/index.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n".getBytes(StandardCharsets.US_ASCII);
		var result = HttpUtil.removeDustAtEndOfCookieHeader(request);
		assertArrayEquals(expect, result);
	}

	@Test
	void extractContentTypeTextCharset() {
		assertEquals(StandardCharsets.UTF_8, HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-Type: text/html; charset=UTF-8")));
	}
	@Test
	void extractContentTypeTextCharset_case() {
		assertEquals(StandardCharsets.UTF_8, HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-type: text/html; Charset=utf-8")));
	}
	@Test
	void extractContentTypeTextCharset_space() {
		assertEquals(StandardCharsets.UTF_8, HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-Type:text/html;charset=UTF-8 ")));
	}
	@Test
	void extractContentTypeTextCharset_tab() {
		assertEquals(StandardCharsets.UTF_8, HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-Type:	text/html;	charset	=	UTF-8	")));
	}
	@Test
	void extractContentTypeTextCharset_quoto() {
		assertEquals(StandardCharsets.UTF_8, HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-Type: text/html; charset=\"UTF-8\"")));
	}
	@Test
	void extractContentTypeTextCharset_params() {
		assertEquals(StandardCharsets.UTF_8, HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-Type: text/html; charset=UTF-8; hoge=fuga")));
	}
	@Test
	void extractContentTypeTextCharset_null() {
		assertNull(HttpUtil.extractContentTypeTextCharset(Lists.newArrayList(
				"Content-Type: text/html;")));
	}

	@Test
	void extractContentTypeMultipartBoundary() {
		assertEquals("xxxxxxxx", HttpUtil.extractContentTypeMultipartBoundary(Lists.newArrayList(
				"Content-Type: multipart/form-data;boundary=xxxxxxxx")));
	}
	@Test
	void extractContentTypeMultipartBoundary_general() {
		assertEquals("----BouNdaRy", HttpUtil.extractContentTypeMultipartBoundary(Lists.newArrayList(
				"Content-Type: multipart/form-data;boundary=----BouNdaRy")));
	}
	@Test
	void extractContentTypeMultipartBoundary_byteranges() {
		assertEquals("yyyyyyyyyyyyy", HttpUtil.extractContentTypeMultipartBoundary(Lists.newArrayList(
				"Content-Type: multipart/byteranges; boundary=yyyyyyyyyyyyy")));
	}

	@Test
	void extractMessageBody() {
		assertEquals("<html><body>hoge</body></html>", HttpUtil.extractMessageBody(
				"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 30\r\n" +
				"\r\n" +
				"<html><body>hoge</body></html>"));
	}
	@Test
	void extractMessageBody_empty() {
		assertEquals("", HttpUtil.extractMessageBody(
				"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n"));
	}
	@Test
	void extractMessageBody_separater_none() {
		assertEquals("", HttpUtil.extractMessageBody(
				"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 0\r\n"));
	}
	@Test
	void extractMessageBody_separater_multiple() {
		assertEquals(
				"<html><body>hoge\r\n" +
				"\r\n" +
				"fuga</body></html>"
				, HttpUtil.extractMessageBody(
				"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 38\r\n" +
				"\r\n" +
				"<html><body>hoge\r\n" +
				"\r\n" +
				"fuga</body></html>"));
	}

	@Test
	void convertMessageBytesToString_multipart() {
		var data = Lists.newArrayList(
			new StringWithCharset(StandardCharsets.ISO_8859_1, "POST /example HTTP/1.1"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Host: localhost"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: multipart/form-data; boundary=----0123456789abcdefghijklmnopqrstuvwxyz"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Length: 999"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------0123456789abcdefghijklmnopqrstuvwxyz"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: text/plain; charset=utf-8"), // UTF-8
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.UTF_8,      "あいうえお"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------0123456789abcdefghijklmnopqrstuvwxyz"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: text/plain; charset=sjis"), // SJIS
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(Charset.forName("SJIS"),      "あいうえお"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------0123456789abcdefghijklmnopqrstuvwxyz"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: text/plain"), // without charset param
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.UTF_8,      "あいうえお"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------0123456789abcdefghijklmnopqrstuvwxyz"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: multipart/form-data; boundary=----ABCDEFG"), //nested multipart
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------ABCDEFG"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: text/plain; charset=utf-8"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.UTF_8,      "あいうえお"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------ABCDEFG--"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "------0123456789abcdefghijklmnopqrstuvwxyz--")
		);

		var dataBytes = dataToBytes(data);
		var bodyOffset = new String(dataBytes, StandardCharsets.ISO_8859_1).indexOf("\r\n\r\n") + "\r\n\r\n".length();

		assertEquals(dataToStr(data), HttpUtil.convertMessageBytesToString(dataBytes, dataToHeaders(data), bodyOffset));
	}
	private String dataToStr(List<StringWithCharset> data) {
		var ret = new StringBuilder();
		for(var d: data) {
			ret.append(d.str);
			ret.append("\r\n");
		}
		return ret.toString();
	}
	private byte[] dataToBytes(List<StringWithCharset> data) {
		var ret = new byte[] {};
		for(var d: data) {
			ret = ArrayUtils.addAll(ret, (d.str + "\r\n").getBytes(d.charset));
		}
		return ret;
	}
	private List<String> dataToHeaders(List<StringWithCharset> data) {
		List<String> headers = Lists.newArrayList();
		for(var d: data) {
			headers.add(d.str);
			if(d.str.equals("")) {
				break;
			}
		}
		return headers;
	}
	private class StringWithCharset {
		private final String str;
		private final Charset charset;
		private StringWithCharset(Charset charset, String str) {
			this.str = str;
			this.charset = charset;
		}
	}

	@Test
	void convertMessageBytesToString_multipart_boundary_chars() {
		var boundary = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')(+_,-./:=?"; //see: https://datatracker.ietf.org/doc/html/rfc2046#page-21
		var data = Lists.newArrayList(
			new StringWithCharset(StandardCharsets.ISO_8859_1, "POST /example HTTP/1.1"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Host: localhost"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: multipart/form-data; boundary=" + boundary),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Length: 999"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "--" + boundary),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "Content-Type: text/plain; charset=utf-8"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, ""),
			new StringWithCharset(StandardCharsets.UTF_8,      "あいうえお"),
			new StringWithCharset(StandardCharsets.ISO_8859_1, "--" + boundary + "--")
		);

		var dataBytes = dataToBytes(data);
		var bodyOffset = new String(dataBytes, StandardCharsets.ISO_8859_1).indexOf("\r\n\r\n") + "\r\n\r\n".length();

		assertEquals(dataToStr(data), HttpUtil.convertMessageBytesToString(dataBytes, dataToHeaders(data), bodyOffset));
	}

	@Test
	void createAuthorizationBearerHeader_() {
		var result = HttpUtil.createAuthorizationBearerHeader("aaa.bbb.ccc");
		assertEquals("Authorization: Bearer aaa.bbb.ccc", result);
	}

}
