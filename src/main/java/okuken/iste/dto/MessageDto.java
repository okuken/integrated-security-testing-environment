package okuken.iste.dto;

import java.util.List;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class MessageDto {

	private Integer id;

	private String name;

	private String method;
	private String url;
	private Integer params;
	private Short status;
	private Integer length;
	private String mimeType;
	private String cookies;

	private List<MessageParamDto> messageParamList;

	private Integer messageRawId;
	private IHttpRequestResponse message;
	private IRequestInfo requestInfo;
	private IResponseInfo responseInfo;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getMethod() {
		return method;
	}
	public void setMethod(String method) {
		this.method = method;
	}
	public String getUrl() {
		return url;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public Integer getParams() {
		return params;
	}
	public void setParams(Integer params) {
		this.params = params;
	}
	public Short getStatus() {
		return status;
	}
	public void setStatus(Short status) {
		this.status = status;
	}
	public Integer getLength() {
		return length;
	}
	public void setLength(Integer length) {
		this.length = length;
	}
	public String getMimeType() {
		return mimeType;
	}
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}
	public String getCookies() {
		return cookies;
	}
	public void setCookies(String cookies) {
		this.cookies = cookies;
	}
	public List<MessageParamDto> getMessageParamList() {
		return messageParamList;
	}
	public void setMessageParamList(List<MessageParamDto> messageParamList) {
		this.messageParamList = messageParamList;
	}
	public Integer getMessageRawId() {
		return messageRawId;
	}
	public void setMessageRawId(Integer messageRawId) {
		this.messageRawId = messageRawId;
	}
	public IHttpRequestResponse getMessage() {
		return message;
	}
	public void setMessage(IHttpRequestResponse message) {
		this.message = message;
	}
	public IRequestInfo getRequestInfo() {
		return requestInfo;
	}
	public void setRequestInfo(IRequestInfo requestInfo) {
		this.requestInfo = requestInfo;
	}
	public IResponseInfo getResponseInfo() {
		return responseInfo;
	}
	public void setResponseInfo(IResponseInfo responseInfo) {
		this.responseInfo = responseInfo;
	}

}