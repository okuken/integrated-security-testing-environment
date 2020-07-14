package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

import burp.IHttpService;
import burp.IMessageEditorController;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.view.message.editor.MessageEditorPanel;
import javax.swing.JButton;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.concurrent.Executors;
import java.awt.event.ActionEvent;

public class RepeaterPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private RepeatTablePanel repeatTablePanel;
	private MessageEditorPanel messageEditorPanel;

	private MessageDto orgMessageDto;

	public RepeaterPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		add(splitPane);
		
		JPanel headerPanel = new JPanel();
		splitPane.setLeftComponent(headerPanel);
		headerPanel.setLayout(new BorderLayout(0, 0));
		
		repeatTablePanel = new RepeatTablePanel();
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
					MessageRepeatDto messageRepeatDto = Controller.getInstance().sendRequest(messageEditorPanel.getRequest(), Controller.getInstance().getSelectedMessage());
					SwingUtilities.invokeLater(() -> {
						messageEditorPanel.setResponse(messageRepeatDto.getMessage().getResponse());
						repeatTablePanel.setup(orgMessageDto.getId());
						repeatTablePanel.selectLastRow();
					});
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

	public void setup(MessageDto orgMessageDto) {
		this.orgMessageDto = orgMessageDto;
		repeatTablePanel.setup(orgMessageDto.getId()); //TODO: should cache repeat data or not??

		Integer lastRowIndex = repeatTablePanel.selectLastRow();
		if(lastRowIndex == null) {
			messageEditorPanel.setMessage(orgMessageDto);
			return;
		}
		setMessage(lastRowIndex);
	}

	public void setMessage(int rowIndex) {
		MessageRepeatDto messageRepeatDto = repeatTablePanel.getRow(rowIndex);
		messageEditorPanel.setRequest(messageRepeatDto.getMessage().getRequest());
		messageEditorPanel.setResponse(messageRepeatDto.getMessage().getResponse());
	}

	public void clear() {
		repeatTablePanel.clear();
		messageEditorPanel.clearMessage();
	}

}
