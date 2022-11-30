package okuken.iste.view.message.editor;

import java.awt.BorderLayout;
import java.util.Arrays;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.text.JTextComponent;

import okuken.iste.client.BurpApiClient;
import okuken.iste.consts.Captions;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpServiceDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

public class MessageEditorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private HttpMessageEditor requestMessageEditor;
	private JTextComponent requestMessageEditorTextComponent;

	private HttpMessageEditor responseMessageEditor;

	private HttpServiceDto httpService;

	private JSplitPane splitPane;
	private JTabbedPane tabbedPane;

	public MessageEditorPanel() {
		this(null, false, false);
	}
	public MessageEditorPanel(boolean requestEditable, boolean responseEditable) {
		this(null, requestEditable, responseEditable);
	}
	public MessageEditorPanel(HttpMessageEditorController aMessageEditorController, boolean requestEditable, boolean responseEditable) {
		this(aMessageEditorController, requestEditable, responseEditable, MessageEditorsLayoutType.HORIZONTAL_SPLIT);
	}
	public MessageEditorPanel(HttpMessageEditorController aMessageEditorController, boolean requestEditable, boolean responseEditable, MessageEditorsLayoutType type) {
		setLayout(new BorderLayout(0, 0));

		var messageEditorController = aMessageEditorController;
		if(messageEditorController == null) {
			messageEditorController = createDefaultMessageEditorController();
		}

		requestMessageEditor = BurpApiClient.i().createMessageEditor(messageEditorController, requestEditable);
		responseMessageEditor = BurpApiClient.i().createMessageEditor(messageEditorController, responseEditable);

		setupMessageEditorsLayout(type);
	}

	public void setupMessageEditorsLayout(MessageEditorsLayoutType type) {

		Arrays.stream(getComponents()).filter(c -> c == splitPane || c == tabbedPane).forEach(c -> remove(c));
		splitPane = null;
		tabbedPane = null;

		switch (type) {
		case HORIZONTAL_SPLIT:
		case VERTICAL_SPLIT:
			splitPane = new JSplitPane(type.getOrientation(),
					requestMessageEditor.getComponent(),
					responseMessageEditor.getComponent()
				);
			splitPane.setResizeWeight(0.5);
			add(splitPane);
			break;
		case TAB:
			tabbedPane = new JTabbedPane(JTabbedPane.TOP);
			tabbedPane.addTab(Captions.TAB_MESSAGE_EDITOR_REQUEST, null, requestMessageEditor.getComponent(), null);
			tabbedPane.addTab(Captions.TAB_MESSAGE_EDITOR_RESPONSE, null, responseMessageEditor.getComponent(), null);
			add(tabbedPane);
			break;
		default:
			break;
		}

		UiUtil.repaint(this);
	}

	private HttpMessageEditorController createDefaultMessageEditorController() {
		return new HttpMessageEditorController() {
			@Override
			public HttpServiceDto getHttpService() {
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

	public HttpServiceDto getHttpService() {
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

	public void setMessage(HttpRequestResponseDto message) {
		setMessage(message, false);
	}
	public void setMessage(HttpRequestResponseDto message, boolean keepCaretPosition) {
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