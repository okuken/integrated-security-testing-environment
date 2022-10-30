package okuken.iste.dto;

public class HttpRequestResponseDto {

	private byte[] request;
	private byte[] response;
	private String comment;
	private String highlight;
	private HttpServiceDto httpService;

	public HttpRequestResponseDto(byte[] request, byte[] response, HttpServiceDto httpService) {
		this.request = request;
		this.response = response;
		this.httpService = httpService;
	}

	public byte[] getRequest() {
		return request;
	}

	public void setRequest(byte[] request) {
		this.request = request;
	}

	public byte[] getResponse() {
		return response;
	}


	public void setResponse(byte[] response) {
		this.response = response;
	}

	public String getComment() {
		return comment;
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	public String getHighlight() {
		return highlight;
	}

	public void setHighlight(String highlight) {
		this.highlight = highlight;
	}

	public HttpServiceDto getHttpService() {
		return httpService;
	}

	public void setHttpService(HttpServiceDto httpService) {
		this.httpService = httpService;
	}


	@Override
	public HttpRequestResponseDto clone() {
		var ret = new HttpRequestResponseDto(
				request != null ? request.clone() : null,
				response != null ? response.clone() : null,
				new HttpServiceDto(httpService.getHost(), httpService.getPort(), httpService.getProtocol()));
		ret.setComment(comment);
		ret.setHighlight(highlight);
		return ret;
	}
}
