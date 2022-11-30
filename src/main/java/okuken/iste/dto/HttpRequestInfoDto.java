package okuken.iste.dto;

import java.net.URL;
import java.util.List;

public class HttpRequestInfoDto {

	private final String method;
	private final URL url;
	private final List<String> headers;
	private final List<HttpRequestParameterDto> parameters;
	private final int bodyOffset;
	private final byte contentType;

	public HttpRequestInfoDto(String method, URL url, List<String> headers, List<HttpRequestParameterDto> parameters,
			int bodyOffset, byte contentType) {
		this.method = method;
		this.url = url;
		this.headers = headers;
		this.parameters = parameters;
		this.bodyOffset = bodyOffset;
		this.contentType = contentType;
	}

	public String getMethod() {
		return method;
	}
	public URL getUrl() {
		return url;
	}
	public List<String> getHeaders() {
		return headers;
	}
	public List<HttpRequestParameterDto> getParameters() {
		return parameters;
	}
	public int getBodyOffset() {
		return bodyOffset;
	}
	public byte getContentType() {
		return contentType;
	}

}
