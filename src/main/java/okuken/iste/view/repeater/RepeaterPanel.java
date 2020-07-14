package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import javax.swing.JSplitPane;

import okuken.iste.dto.MessageDto;
import okuken.iste.view.message.editor.MessageEditorPanel;

public class RepeaterPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private MessageEditorPanel messageEditorPanel;

	public RepeaterPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		add(splitPane);
		
		JPanel headerPanel = new JPanel();
		splitPane.setLeftComponent(headerPanel);
		headerPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel repeatTablePanel = new RepeatTablePanel();
		headerPanel.add(repeatTablePanel, BorderLayout.CENTER);
		
		JPanel controlPanel = new JPanel();
		headerPanel.add(controlPanel, BorderLayout.EAST);
		
		messageEditorPanel = new MessageEditorPanel(/*TODO create IMessageEditorController*/);
		splitPane.setRightComponent(messageEditorPanel);
		
	}

	public void setMessage(MessageDto dto) {
		messageEditorPanel.setMessage(dto);
	}

	public void clearMessage() {
		messageEditorPanel.clearMessage();
	}

}
