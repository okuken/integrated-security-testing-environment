package okuken.iste.dto;

import java.util.Date;

import okuken.iste.enums.ResponseParameterType;

public class MessageCookieDto extends MessageResponseParamDto {

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
	public ResponseParameterType getType() {
		return ResponseParameterType.COOKIE;
	}
	@Override
	public String toString() {
		return super.getName();
	}

}
