package okuken.iste.dto;

public interface HttpMessageEditorController {
	HttpServiceDto getHttpService();
	byte[] getRequest();
	byte[] getResponse();
}
