package okuken.iste.plugin.dto;

import okuken.iste.plugin.api.IIsteMessageAnalyzedInfo;

public class IsteMessageAnalyzedInfo implements IIsteMessageAnalyzedInfo {

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

}
