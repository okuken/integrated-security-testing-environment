package okuken.iste.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

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
	void createAuthorizationBearerHeader_() {
		var result = HttpUtil.createAuthorizationBearerHeader("aaa.bbb.ccc");
		assertEquals("Authorization: Bearer aaa.bbb.ccc", result);
	}

}
