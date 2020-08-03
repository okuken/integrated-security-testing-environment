package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import okuken.iste.dto.MessageDto;
import okuken.iste.view.message.editor.MessageEditorPanel;

public class RepeatMasterPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private MessageEditorPanel messageEditorPanel;

	private MessageDto messageDto;

	public RepeatMasterPanel() {
		setLayout(new BorderLayout(0, 0));
		
		messageEditorPanel = new MessageEditorPanel(false, false);
		add(messageEditorPanel, BorderLayout.CENTER);
		
	}

	public void setup(MessageDto messageDto) {
		this.messageDto = messageDto;
		refreshPanel();
	}

	public void refreshPanel() {
		if(messageDto.getRepeatMasterMessage() == null) {
			messageEditorPanel.setMessage(messageDto); //set org message
			return;
		}

		messageEditorPanel.setMessage(messageDto.getRepeatMasterMessage());
	}

	public void clear() {
		messageEditorPanel.clearMessage();
	}

}
