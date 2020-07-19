package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

import burp.IHttpService;
import burp.IMessageEditorController;
import okuken.iste.consts.Captions;
import okuken.iste.consts.Positions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.view.message.editor.MessageEditorPanel;
import javax.swing.JButton;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.concurrent.Executors;
import java.awt.event.ActionEvent;
import javax.swing.JComboBox;

public class RepeaterPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JSplitPane splitPane;
	private RepeatTablePanel repeatTablePanel;
	private MessageEditorPanel messageEditorPanel;

	private JComboBox<AuthAccountDto> authAccountComboBox;
	private JButton authSessionRefreshButton;

	private MessageDto orgMessageDto;

	public RepeaterPanel() {
		setLayout(new BorderLayout(0, 0));
		
		splitPane = new JSplitPane();
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
		
		JButton sendButton = new JButton(Captions.REPEATER_BUTTON_SEND);
		sendButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				AuthAccountDto authAccountDto = authAccountComboBox.getItemAt(authAccountComboBox.getSelectedIndex());
				Executors.newSingleThreadExecutor().submit(() -> {
					messageEditorPanel.clearResponse();
					MessageRepeatDto messageRepeatDto = Controller.getInstance().sendRepeaterRequest(messageEditorPanel.getRequest(), authAccountDto, Controller.getInstance().getSelectedMessage());
					SwingUtilities.invokeLater(() -> {
						messageEditorPanel.setResponse(messageRepeatDto.getMessage().getResponse());
						repeatTablePanel.setup(orgMessageDto.getId());
						repeatTablePanel.selectLastRow();
					});
				});
			}
		});
		controlPanel.add(sendButton);
		
		authAccountComboBox = new JComboBox<AuthAccountDto>();
		authAccountComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				authSessionRefreshButton.setEnabled(authAccountComboBox.getSelectedIndex() > 0);
			}
		});
		controlPanel.add(authAccountComboBox);
		
		authSessionRefreshButton = new JButton(Captions.REPEATER_BUTTON_AUTH_SESSION_REFRESH);
		authSessionRefreshButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = authAccountComboBox.getSelectedIndex();
				if(selectedIndex < 1) {
					return;
				}
				Executors.newSingleThreadExecutor().submit(() -> {
					Controller.getInstance().fetchNewAuthSession(authAccountComboBox.getItemAt(selectedIndex));
				});
			}
		});
		controlPanel.add(authSessionRefreshButton);
		
		JButton copyOrgButton = new JButton(Captions.REPEATER_BUTTON_COPY_ORG);
		copyOrgButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.setMessage(orgMessageDto);
			}
		});
		controlPanel.add(copyOrgButton);
		
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
		
		
		SwingUtilities.invokeLater(() -> {
			initDividerLocation();
		});
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

	public void refreshAuthAccountsComboBox() {
		authAccountComboBox.removeAllItems();
		authAccountComboBox.addItem(new AuthAccountDto());
		authSessionRefreshButton.setEnabled(false);

		if(ConfigLogic.getInstance().getAuthConfig() == null) {
			return;
		}

		Controller.getInstance().getAuthAccounts().forEach(authAccount -> {
			authAccountComboBox.addItem(authAccount);
		});
	}

	public void clear() {
		repeatTablePanel.clear();
		messageEditorPanel.clearMessage();
	}

	public void initDividerLocation() {
		splitPane.setDividerLocation(Positions.DIVIDER_LOCATION_REPEATER);
	}

}
