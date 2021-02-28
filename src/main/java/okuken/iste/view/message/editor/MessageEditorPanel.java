package okuken.iste.view.message.editor;

import java.awt.BorderLayout;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import okuken.iste.consts.Captions;
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
		this(aMessageEditorController, requestEditable, responseEditable, false);
	}
	public MessageEditorPanel(IMessageEditorController aMessageEditorController, boolean requestEditable, boolean responseEditable, boolean tabMode) {
		setLayout(new BorderLayout(0, 0));

		var messageEditorController = aMessageEditorController;
		if(messageEditorController == null) {
			messageEditorController = createDefaultMessageEditorController();
		}

		requestMessageEditor = BurpUtil.getCallbacks().createMessageEditor(messageEditorController, requestEditable);
		responseMessageEditor = BurpUtil.getCallbacks().createMessageEditor(messageEditorController, responseEditable);

		if(tabMode) {
			JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
			tabbedPane.addTab(Captions.TAB_MESSAGE_EDITOR_REQUEST, null, requestMessageEditor.getComponent(), null);
			tabbedPane.addTab(Captions.TAB_MESSAGE_EDITOR_RESPONSE, null, responseMessageEditor.getComponent(), null);
			add(tabbedPane);
			return;
		}

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

	public int[] getRequestSelectionBounds() {
		return requestMessageEditor.getSelectionBounds();
	}

	public byte[] getResponse() {
		return responseMessageEditor.getMessage();
	}

	public IHttpService getHttpService() {
		return httpService;
	}

	public void setRequest(byte[] request) {
		requestMessageEditor.setMessage(request, true);
	}

	public void setMessage(MessageDto dto) {
		setMessage(dto.getMessage());
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