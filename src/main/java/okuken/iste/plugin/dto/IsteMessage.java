package okuken.iste.plugin.dto;

import okuken.iste.plugin.api.IIsteMessage;

public class IsteMessage implements IIsteMessage {

	private String protocol;
	private String host;
	private Integer port;

	private byte[] request;
	private byte[] response;


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

}
