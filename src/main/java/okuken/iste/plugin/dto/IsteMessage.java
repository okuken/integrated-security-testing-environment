package okuken.iste.plugin.dto;

import okuken.iste.plugin.api.IIsteMessage;

public class IsteMessage implements IIsteMessage {

	private String protocol;
	private String host;
	private Integer port;
	private byte[] request;
	private byte[] response;

	private String url;
	private String urlWithoutQuery;
	private String method;
	private String path;
	private String query;
	private Integer paramCount;
	private Short status;
	private Integer length;
	private String mimeType;
	private String cookies;

	private String name;
	private String remark;
	private String priority;
	private String progress;
	private String progressNotes;
	private String notes;

	@Override
	public String getProtocol() {
		return protocol;
	}
	@Override
	public String getHost() {
		return host;
	}
	@Override
	public Integer getPort() {
		return port;
	}
	@Override
	public byte[] getRequest() {
		return request;
	}
	@Override
	public byte[] getResponse() {
		return response;
	}
	@Override
	public String getUrl() {
		return url;
	}
	@Override
	public String getUrlWithoutQuery() {
		return urlWithoutQuery;
	}
	@Override
	public String getMethod() {
		return method;
	}
	@Override
	public String getPath() {
		return path;
	}
	@Override
	public String getQuery() {
		return query;
	}
	@Override
	public Integer getParamCount() {
		return paramCount;
	}
	@Override
	public Short getStatus() {
		return status;
	}
	@Override
	public Integer getLength() {
		return length;
	}
	@Override
	public String getMimeType() {
		return mimeType;
	}
	@Override
	public String getCookies() {
		return cookies;
	}
	@Override
	public String getName() {
		return name;
	}
	@Override
	public String getRemark() {
		return remark;
	}
	@Override
	public String getPriority() {
		return priority;
	}
	@Override
	public String getProgress() {
		return progress;
	}
	@Override
	public String getProgressNotes() {
		return progressNotes;
	}
	@Override
	public String getNotes() {
		return notes;
	}


	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	public void setHost(String host) {
		this.host = host;
	}
	public void setPort(Integer port) {
		this.port = port;
	}
	public void setRequest(byte[] request) {
		this.request = request;
	}
	public void setResponse(byte[] response) {
		this.response = response;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public void setUrlWithoutQuery(String urlWithoutQuery) {
		this.urlWithoutQuery = urlWithoutQuery;
	}
	public void setMethod(String method) {
		this.method = method;
	}
	public void setPath(String path) {
		this.path = path;
	}
	public void setQuery(String query) {
		this.query = query;
	}
	public void setParamCount(Integer paramCount) {
		this.paramCount = paramCount;
	}
	public void setStatus(Short status) {
		this.status = status;
	}
	public void setLength(Integer length) {
		this.length = length;
	}
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}
	public void setCookies(String cookies) {
		this.cookies = cookies;
	}
	public void setName(String name) {
		this.name = name;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	public void setPriority(String priority) {
		this.priority = priority;
	}
	public void setProgress(String progress) {
		this.progress = progress;
	}
	public void setProgressNotes(String progressNotes) {
		this.progressNotes = progressNotes;
	}
	public void setNotes(String notes) {
		this.notes = notes;
	}

}
