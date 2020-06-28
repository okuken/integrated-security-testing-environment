package okuken.iste.view.message.editor;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;

public class MessageEditorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public MessageEditorPanel() {
		setLayout(new BorderLayout(0, 0));

		IBurpExtenderCallbacks callbacks = BurpUtil.getCallbacks();
		if(callbacks == null) { // case: Visual Editor...
			return;
		}

		IMessageEditor requestMessageEditor = callbacks.createMessageEditor(new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return Controller.getInstance().getSelectedMessage().getHttpService();
			}
			@Override
			public byte[] getRequest() {
				return Controller.getInstance().getSelectedMessage().getRequest();
			}
			@Override
			public byte[] getResponse() {
				return null;
			}
		}, false);
		Controller.getInstance().setRequestMessageEditor(requestMessageEditor);

		IMessageEditor responseMessageEditor = callbacks.createMessageEditor(new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return Controller.getInstance().getSelectedMessage().getHttpService();
			}
			@Override
			public byte[] getRequest() {
				return null;
			}
			@Override
			public byte[] getResponse() {
				return Controller.getInstance().getSelectedMessage().getResponse();
			}
		}, false);
		Controller.getInstance().setResponseMessageEditor(responseMessageEditor);

		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
				requestMessageEditor.getComponent(),
				responseMessageEditor.getComponent()
			);
		splitPane.setResizeWeight(0.5);

		add(splitPane);
	}
	
}