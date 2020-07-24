package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import burp.IHttpService;
import burp.IMessageEditorController;
import okuken.iste.dto.MessageDto;
import okuken.iste.view.message.editor.MessageEditorPanel;

public class RepeatMasterPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private MessageEditorPanel messageEditorPanel;

	private MessageDto messageDto;

	public RepeatMasterPanel() {
		setLayout(new BorderLayout(0, 0));
		
		messageEditorPanel = new MessageEditorPanel(new IMessageEditorController() {
			@Override
			public byte[] getResponse() {
				return messageEditorPanel.getResponse();
			}
			@Override
			public byte[] getRequest() {
				return messageEditorPanel.getRequest();
			}
			@Override
			public IHttpService getHttpService() {
				return messageDto.getMessage().getHttpService();
			}
		}, false, false);
		add(messageEditorPanel, BorderLayout.CENTER);
		
	}

	public void setup(MessageDto messageDto) {
		this.messageDto = messageDto;
		refreshPanel();
	}

	public void refreshPanel() {
		if(messageDto.getRepeatMasterMessage() == null) {
			messageEditorPanel.setMessage(messageDto);
			return;
		}

		messageEditorPanel.setMessage(messageDto.getRepeatMasterMessage());
	}

	public void clear() {
		messageEditorPanel.clearMessage();
	}

}
