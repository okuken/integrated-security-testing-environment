package okuken.iste.dto.burp;

import burp.IHttpRequestResponse;
import burp.IHttpService;

public class HttpRequestResponseMock implements IHttpRequestResponse {

	private byte[] request;
	private byte[] response;
	private String comment;
	private String highlight;
	private IHttpService httpService;

	public HttpRequestResponseMock() {
	}

	public HttpRequestResponseMock(byte[] request, byte[] response, IHttpService httpService) {
		this.request = request;
		this.response = response;
		this.httpService = httpService;
	}

	@Override
	public byte[] getRequest() {
		return request;
	}

	@Override
	public void setRequest(byte[] request) {
		this.request = request;
	}

	@Override
	public byte[] getResponse() {
		return response;
	}

	@Override
	public void setResponse(byte[] response) {
		this.response = response;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void setComment(String comment) {
		this.comment = comment;
	}

	@Override
	public String getHighlight() {
		return highlight;
	}

	@Override
	public void setHighlight(String highlight) {
		this.highlight = highlight;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

	@Override
	public void setHttpService(IHttpService httpService) {
		this.httpService = httpService;
	}


	@Override
	public HttpRequestResponseMock clone() {
		var ret = new HttpRequestResponseMock();
		ret.setRequest(request.clone());
		ret.setResponse(response.clone());
		ret.setComment(comment);
		ret.setHighlight(highlight);
		ret.setHttpService(new HttpServiceMock(httpService.getHost(), httpService.getPort(), httpService.getProtocol()));
		return ret;
	}

}
