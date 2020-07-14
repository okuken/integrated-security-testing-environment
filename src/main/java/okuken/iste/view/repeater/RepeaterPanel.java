package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import javax.swing.JSplitPane;

import burp.IHttpService;
import burp.IMessageEditorController;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.view.message.editor.MessageEditorPanel;
import javax.swing.JButton;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.concurrent.Executors;
import java.awt.event.ActionEvent;

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
		FlowLayout flowLayout = (FlowLayout) controlPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		headerPanel.add(controlPanel, BorderLayout.SOUTH);
		
		JButton btnNewButton = new JButton(Captions.REPEATER_BUTTON_SEND);
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Executors.newSingleThreadExecutor().submit(() -> {
					messageEditorPanel.clearResponse();
					MessageDto messageDto = Controller.getInstance().sendRequest(messageEditorPanel.getRequest(), Controller.getInstance().getSelectedMessage());
					messageEditorPanel.setResponse(messageDto.getMessage().getResponse());
				});
			}
		});
		controlPanel.add(btnNewButton);
		
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
				return Controller.getInstance().getSelectedMessage().getMessage().getHttpService();
			}
		}, true, false);
		splitPane.setRightComponent(messageEditorPanel);
		
	}

	public void setMessage(MessageDto dto) {
		messageEditorPanel.setMessage(dto);
	}

	public void clearMessage() {
		messageEditorPanel.clearMessage();
	}

}
