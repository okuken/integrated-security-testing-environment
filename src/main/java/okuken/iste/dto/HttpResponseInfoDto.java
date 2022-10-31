package okuken.iste.dto;

import java.util.List;

public class HttpResponseInfoDto {

	private final List<String> headers;
	private final int bodyOffset;
	private final short statusCode;
	private final List<HttpCookieDto> cookies;
	private final String statedMimeType;
	private final String inferredMimeType;

	public HttpResponseInfoDto(List<String> headers, int bodyOffset, short statusCode, List<HttpCookieDto> cookies,
			String statedMimeType, String inferredMimeType) {
		this.headers = headers;
		this.bodyOffset = bodyOffset;
		this.statusCode = statusCode;
		this.cookies = cookies;
		this.statedMimeType = statedMimeType;
		this.inferredMimeType = inferredMimeType;
	}

	public List<String> getHeaders() {
		return headers;
	}
	public int getBodyOffset() {
		return bodyOffset;
	}
	public short getStatusCode() {
		return statusCode;
	}
	public List<HttpCookieDto> getCookies() {
		return cookies;
	}
	public String getStatedMimeType() {
		return statedMimeType;
	}
	public String getInferredMimeType() {
		return inferredMimeType;
	}

}
