package okuken.iste.view.message.editor;

import java.awt.BorderLayout;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.text.JTextComponent;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

public class MessageEditorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private IMessageEditor requestMessageEditor;
	private JTextComponent requestMessageEditorTextComponent;

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

	private JTextComponent getRequestTextComponent() {
		if(requestMessageEditorTextComponent == null) {
			requestMessageEditorTextComponent = BurpUtil.extractMessageEditorTextComponent(requestMessageEditor);
		}
		return requestMessageEditorTextComponent;
	}

	public byte[] getResponse() {
		return responseMessageEditor.getMessage();
	}

	public IHttpService getHttpService() {
		return httpService;
	}

	public void setRequest(byte[] request) {
		setRequest(request, false);
	}
	public void setRequest(byte[] request, boolean keepCaretPosition) {
		if(keepCaretPosition) {
			UiUtil.withKeepCaretPosition(getRequestTextComponent(), () -> {
				requestMessageEditor.setMessage(request, true);
			});
			return;
		}

		requestMessageEditor.setMessage(request, true);
	}

	public void setResponse(byte[] response) {
		responseMessageEditor.setMessage(Optional.ofNullable(response).orElse(new byte[] {}), false);
	}

	public void setMessage(MessageDto dto) {
		setMessage(dto, false);
	}
	public void setMessage(MessageDto dto, boolean keepCaretPosition) {
		setMessage(dto.getMessage(), keepCaretPosition);
	}

	public void setMessage(IHttpRequestResponse message) {
		setMessage(message, false);
	}
	public void setMessage(IHttpRequestResponse message, boolean keepCaretPosition) {
		setRequest(message.getRequest(), keepCaretPosition);
		setResponse(message.getResponse());
		httpService = message.getHttpService();
	}

	public void clearMessage() {
		setRequest(new byte[] {});
		setResponse(new byte[] {});
		httpService = null;
	}

	public void clearResponse() {
		setResponse(new byte[] {});
	}

	public void focusRequest() {
		var component = getRequestTextComponent();
		if(component != null) {
			UiUtil.focus(component);
		}
	}

}