package okuken.iste.dto;

import java.util.Date;

import burp.IParameter;

public class MessageCookieDto extends MessageParamDto {

	private String domain;
	private String path;
	private Date expiration;

	public String getDomain() {
		return domain;
	}
	public void setDomain(String domain) {
		this.domain = domain;
	}
	public String getPath() {
		return path;
	}
	public void setPath(String path) {
		this.path = path;
	}
	public Date getExpiration() {
		return expiration;
	}
	public void setExpiration(Date expiration) {
		this.expiration = expiration;
	}

	@Override
	public byte getType() {
		return IParameter.PARAM_COOKIE;
	}
	@Override
	public String toString() {
		return super.getName();
	}

}
