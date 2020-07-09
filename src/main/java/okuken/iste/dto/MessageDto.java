package okuken.iste.dto;

import java.net.URL;
import java.util.List;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import okuken.iste.logic.MessageLogic;

public class MessageDto {

	private Integer id;

	private String name;
	private String remark;

	private String method;
	private URL url;
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

	public String getProtocol() {
		if(url == null) {return null;}
		return url.getProtocol();
	}
	public String getHost() {
		if(url == null) {return null;}
		return url.getHost();
	}
	public Integer getPort() {
		if(url == null) {return null;}
		return url.getPort() != -1 ? url.getPort() : null;
	}
	public Integer getPortIfNotDefault() {
		if(url == null) {return null;}
		return url.getPort() != url.getDefaultPort() ? url.getPort() : null; 
	}
	public String getPath() {
		if(url == null) {return null;}
		return url.getPath();
	}
	public String getQuery() {
		if(url == null) {return null;}
		return url.getQuery();
	}
	/**
	 * not include default port.
	 */
	public String getUrlShort() {
		if(url == null) {return null;}
		return String.format("%s://%s%s", url.getProtocol(), createShortAuthority(url), url.getFile());
	}
	/**
	 * not include default port and GET parameters.
	 */
	public String getUrlShortest() {
		if(url == null) {return null;}
		return String.format("%s://%s%s", url.getProtocol(), createShortAuthority(url), url.getPath());
	}
	private String createShortAuthority(URL url) {
		String authority = url.getAuthority();
		if(url.getPort() == url.getDefaultPort()) {
			authority = authority.substring(0, authority.indexOf(":"));
		}
		return authority;
	}


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
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
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
		if(message == null) {
			MessageLogic.getInstance().loadMessageDetail(this);
		}
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