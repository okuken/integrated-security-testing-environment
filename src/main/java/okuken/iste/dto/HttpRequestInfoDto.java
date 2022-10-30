package okuken.iste.dto;

import java.net.URL;
import java.util.List;

public class HttpRequestInfoDto {

	private String method;
	private URL url;
	private List<String> headers;
	private List<HttpRequestParameterDto> parameters;
	private int bodyOffset;
	private byte contentType;

	public String getMethod() {
		return method;
	}
	public void setMethod(String method) {
		this.method = method;
	}
	public URL getUrl() {
		return url;
	}
	public void setUrl(URL url) {
		this.url = url;
	}
	public List<String> getHeaders() {
		return headers;
	}
	public void setHeaders(List<String> headers) {
		this.headers = headers;
	}
	public List<HttpRequestParameterDto> getParameters() {
		return parameters;
	}
	public void setParameters(List<HttpRequestParameterDto> parameters) {
		this.parameters = parameters;
	}
	public int getBodyOffset() {
		return bodyOffset;
	}
	public void setBodyOffset(int bodyOffset) {
		this.bodyOffset = bodyOffset;
	}
	public byte getContentType() {
		return contentType;
	}
	public void setContentType(byte contentType) {
		this.contentType = contentType;
	}

}
