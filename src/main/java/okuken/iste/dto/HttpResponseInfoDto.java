package okuken.iste.dto;

import java.util.List;

public class HttpResponseInfoDto {

	private List<String> headers;
	private int bodyOffset;
	private short statusCode;
	private List<HttpCookieDto> cookies;
	private String statedMimeType;
	private String inferredMimeType;

	public List<String> getHeaders() {
		return headers;
	}
	public void setHeaders(List<String> headers) {
		this.headers = headers;
	}
	public int getBodyOffset() {
		return bodyOffset;
	}
	public void setBodyOffset(int bodyOffset) {
		this.bodyOffset = bodyOffset;
	}
	public short getStatusCode() {
		return statusCode;
	}
	public void setStatusCode(short statusCode) {
		this.statusCode = statusCode;
	}
	public List<HttpCookieDto> getCookies() {
		return cookies;
	}
	public void setCookies(List<HttpCookieDto> cookies) {
		this.cookies = cookies;
	}
	public String getStatedMimeType() {
		return statedMimeType;
	}
	public void setStatedMimeType(String statedMimeType) {
		this.statedMimeType = statedMimeType;
	}
	public String getInferredMimeType() {
		return inferredMimeType;
	}
	public void setInferredMimeType(String inferredMimeType) {
		this.inferredMimeType = inferredMimeType;
	}

}
