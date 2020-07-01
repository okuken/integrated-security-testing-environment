package okuken.iste.dto;

import java.util.stream.Collectors;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import okuken.iste.util.BurpUtil;

public class MessageDto {

	private String name;

	private IHttpRequestResponse message;
	private IRequestInfo requestInfo;
	private IResponseInfo responseInfo;

	private MessageDto() {}
	public static MessageDto create(IHttpRequestResponse message, String name) {

		MessageDto ret = new MessageDto();
		ret.message = message;
		ret.name = name;

		IExtensionHelpers helpers = BurpUtil.getHelpers();
		ret.requestInfo = helpers.analyzeRequest(message);
		ret.responseInfo = helpers.analyzeResponse(message.getResponse());

		return ret;
	}

	public void setName(String name) {
		this.name = name;
	}

	public IHttpRequestResponse getHttpRequestResponse() {
		return this.message;
	}
	public IRequestInfo getRequestInfo() {
		return this.requestInfo;
	}
	public IResponseInfo getResponseInfo() {
		return this.responseInfo;
	}

	public String getName() {
		return this.name;
	}
	public String getHost() {
		return this.requestInfo.getUrl().getHost();
	}
	public String getMethod() {
		return this.requestInfo.getMethod();
	}
	public String getUrl() {
		return this.requestInfo.getUrl().toExternalForm();
	}
	public String getParams() {
		return Integer.toString(this.requestInfo.getParameters().size());
	}
	public String getStatus() {
		return Short.toString(this.responseInfo.getStatusCode());
	}
	public String getLength() {
		return Integer.toString(this.message.getResponse().length);
	}
	public String getMimeType() {
		return this.responseInfo.getStatedMimeType();
	}
	public String getComment() {
		return this.message.getComment();
	}
	public String getCookies() {
		return this.responseInfo.getCookies().stream()
				.map(cookie -> String.format("%s=%s;", cookie.getName(), cookie.getValue()))
				.collect(Collectors.joining("; "));
	}

}