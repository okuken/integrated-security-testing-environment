package okuken.iste.view.message.editor;

import burp.IMessageEditorController;
import okuken.iste.dto.HttpServiceDto;

public abstract class HttpMessageEditorController implements IMessageEditorController {
	public abstract HttpServiceDto getHttpService();
	public abstract byte[] getRequest();
	public abstract byte[] getResponse();
}
