package okuken.iste.dto;

import java.util.List;
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

	private List<MessageParamDto> messageParamList;

	private MessageDto() {}
	public static MessageDto create(IHttpRequestResponse message, String name) {

		MessageDto ret = new MessageDto();
		ret.message = message;
		ret.name = name;

		IExtensionHelpers helpers = BurpUtil.getHelpers();
		ret.requestInfo = helpers.analyzeRequest(message);
		ret.responseInfo = helpers.analyzeResponse(message.getResponse());

		ret.messageParamList = ret.requestInfo.getParameters().stream()
				.map(parameter -> MessageParamDto.create(parameter)).collect(Collectors.toList());

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
	public Integer getParams() {
		return this.requestInfo.getParameters().size();
	}
	public Short getStatus() {
		return this.responseInfo.getStatusCode();
	}
	public Integer getLength() {
		return this.message.getResponse().length;
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

	public List<MessageParamDto> getMessageParamList() {
		return messageParamList;
	}

}