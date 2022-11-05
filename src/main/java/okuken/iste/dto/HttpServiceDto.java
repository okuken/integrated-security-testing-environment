package okuken.iste.dto;

import burp.IHttpService;

public class HttpServiceDto implements IHttpService {

	private final String host;
	private final int port;
	private final String protocol;

	public HttpServiceDto(String host, int port, String protocol) {
		this.host = host;
		this.port = port;
		this.protocol = protocol;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	public String getProtocol() {
		return protocol;
	}

	@Override
	public HttpServiceDto clone() {
		return new HttpServiceDto(host, port, protocol);
	}

}
