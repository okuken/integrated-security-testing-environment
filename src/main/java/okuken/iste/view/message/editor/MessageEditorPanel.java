package okuken.iste.view.message.editor;

import java.awt.BorderLayout;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JSplitPane;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;

public class MessageEditorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private IMessageEditor requestMessageEditor;
	private IMessageEditor responseMessageEditor;

	private IHttpService httpService;

	public MessageEditorPanel() {
		this(null, false, false);
	}
	public MessageEditorPanel(boolean requestEditable, boolean responseEditable) {
		this(null, requestEditable, responseEditable);
	}
	public MessageEditorPanel(IMessageEditorController aMessageEditorController, boolean requestEditable, boolean responseEditable) {
		setLayout(new BorderLayout(0, 0));

		var messageEditorController = aMessageEditorController;
		if(messageEditorController == null) {
			messageEditorController = createDefaultMessageEditorController();
		}

		requestMessageEditor = BurpUtil.getCallbacks().createMessageEditor(messageEditorController, requestEditable);
		responseMessageEditor = BurpUtil.getCallbacks().createMessageEditor(messageEditorController, responseEditable);

		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
				requestMessageEditor.getComponent(),
				responseMessageEditor.getComponent()
			);
		splitPane.setResizeWeight(0.5);

		add(splitPane);
	}

	private IMessageEditorController createDefaultMessageEditorController() {
		return new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return httpService;
			}
			@Override
			public byte[] getRequest() {
				return requestMessageEditor.getMessage();
			}
			@Override
			public byte[] getResponse() {
				return responseMessageEditor.getMessage();
			}
		};
	}

	public byte[] getRequest() {
		return requestMessageEditor.getMessage();
	}

	public byte[] getResponse() {
		return responseMessageEditor.getMessage();
	}

	public void setMessage(MessageDto dto) {
		requestMessageEditor.setMessage(
				dto.getMessage().getRequest(),
				true);
		responseMessageEditor.setMessage(
				Optional.ofNullable(dto.getMessage().getResponse()).orElse(new byte[] {}),
				false);
		httpService = dto.getMessage().getHttpService();
	}

	public void setMessage(IHttpRequestResponse message) {
		requestMessageEditor.setMessage(message.getRequest(), true);
		responseMessageEditor.setMessage(Optional.ofNullable(message.getResponse()).orElse(new byte[] {}), false);
		httpService = message.getHttpService();
	}

	public void clearMessage() {
		requestMessageEditor.setMessage(new byte[] {}, true);
		responseMessageEditor.setMessage(new byte[] {}, false);
		httpService = null;
	}

	public void clearResponse() {
		responseMessageEditor.setMessage(new byte[] {}, false);
	}

}