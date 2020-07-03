package okuken.iste.dto.burp;

import burp.IHttpService;

public class HttpServiceMock implements IHttpService {

	private final String host;
	private final int port;
	private final String protocol;

	public HttpServiceMock(String host, int port, String protocol) {
		this.host = host;
		this.port = port;
		this.protocol = protocol;
	}

	@Override
	public String getHost() {
		return host;
	}

	@Override
	public int getPort() {
		return port;
	}

	@Override
	public String getProtocol() {
		return protocol;
	}

}
