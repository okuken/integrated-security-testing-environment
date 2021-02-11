package okuken.iste.view.repeater;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.consts.Positions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.dto.MessageRepeatRedirectDto;
import okuken.iste.dto.burp.HttpRequestResponseMock;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.AbstractDockoutableTabPanel;
import okuken.iste.view.chain.ChainDefPanel;
import okuken.iste.view.message.editor.MessageEditorPanel;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JComboBox;
import javax.swing.JLabel;

public class RepeaterPanel extends AbstractDockoutableTabPanel {

	private static final long serialVersionUID = 1L;

	private JSplitPane splitPane;
	private RepeatTablePanel repeatTablePanel;
	private MessageEditorPanel messageEditorPanel;

	private JComboBox<AuthAccountDto> authAccountComboBox;
	private JButton authSessionRefreshButton;
	private JLabel authSessionValueLabel;

	private JButton followRedirectButton;

	private JButton dockoutButton;

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
		headerPanel.add(controlPanel, BorderLayout.SOUTH);
		controlPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel controlLeftPanel = new JPanel();
		controlPanel.add(controlLeftPanel, BorderLayout.WEST);
		
		JButton sendButton = new JButton(Captions.REPEATER_BUTTON_SEND);
		sendButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sendRequest();
			}
		});
		controlLeftPanel.add(sendButton);
		
		authAccountComboBox = new JComboBox<AuthAccountDto>();
		authAccountComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int index = authAccountComboBox.getSelectedIndex();
				authSessionRefreshButton.setEnabled(index > 0);
				authSessionValueLabel.setText(index > 0 ? authAccountComboBox.getItemAt(index).getSessionIdForDisplay() : null);
			}
		});
		controlLeftPanel.add(authAccountComboBox);
		
		authSessionRefreshButton = new JButton(Captions.REPEATER_BUTTON_AUTH_SESSION_REFRESH);
		authSessionRefreshButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = authAccountComboBox.getSelectedIndex();
				if(selectedIndex < 1) { //dummy
					return;
				}

				Controller.getInstance().fetchNewAuthSession(authAccountComboBox.getItemAt(selectedIndex), null);
			}
		});
		controlLeftPanel.add(authSessionRefreshButton);
		
		authSessionValueLabel = new JLabel();
		controlLeftPanel.add(authSessionValueLabel);
		
		JButton copyOrgButton = new JButton(Captions.REPEATER_BUTTON_COPY_ORG);
		copyOrgButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.clearMessage();
				setMessage(orgMessageDto);
			}
		});
		controlLeftPanel.add(copyOrgButton);
		
		JButton copyMasterButton = new JButton(Captions.REPEATER_BUTTON_COPY_MASTER);
		copyMasterButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.clearMessage();
				if(orgMessageDto.getRepeatMasterMessage() != null) {
					setMessage(orgMessageDto.getRepeatMasterMessage());
				} else {
					setMessage(orgMessageDto);
				}
			}
		});
		controlLeftPanel.add(copyMasterButton);
		
		JPanel controlCenterPanel = new JPanel();
		controlPanel.add(controlCenterPanel, BorderLayout.CENTER);
		
		followRedirectButton = new JButton(Captions.REPEATER_BUTTON_FOLLOW_REDIRECT);
		followRedirectButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				followRedirect();
			}
		});
//		controlCenterPanel.add(followRedirectButton); //TODO: impl
		
		JPanel controlRightPanel = new JPanel();
		controlPanel.add(controlRightPanel, BorderLayout.EAST);
		
		JLabel saveAsMasterMessageLabel = UiUtil.createTemporaryMessageArea();
		controlRightPanel.add(saveAsMasterMessageLabel);
		
		JButton saveAsMasterButton = new JButton(Captions.REPEATER_BUTTON_SAVE_AS_MASTER);
		saveAsMasterButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				orgMessageDto.setRepeatMasterMessage(new HttpRequestResponseMock(
						messageEditorPanel.getRequest(),
						messageEditorPanel.getResponse(),
						orgMessageDto.getMessage().getHttpService()));
				Controller.getInstance().saveRepeatMaster(orgMessageDto);
				UiUtil.showTemporaryMessage(saveAsMasterMessageLabel, Captions.MESSAGE_SAVED);
			}
		});
		controlRightPanel.add(saveAsMasterButton);
		
		JButton chainButton = new JButton(Captions.REPEATER_BUTTON_CHAIN);
		chainButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var chainDefPanel = new ChainDefPanel(orgMessageDto, Controller.getInstance().getMessageChainIdByBaseMessageId(orgMessageDto.getId()));
				chainDefPanel.setPopupFrame(UiUtil.popup(orgMessageDto.getName() + Captions.REPEATER_POPUP_TITLE_SUFFIX_CHAIN, chainDefPanel, chainButton, we -> {chainDefPanel.cancel();}));
			}
		});
		controlRightPanel.add(chainButton);
		
		dockoutButton = new JButton();
		controlRightPanel.add(dockoutButton);
		setupDockout();
		
		messageEditorPanel = new MessageEditorPanel(true, true);
		splitPane.setRightComponent(messageEditorPanel);
		
		SwingUtilities.invokeLater(() -> {
			initDividerLocation();
		});
	}

	public void setup(MessageDto orgMessageDto) {
		this.orgMessageDto = orgMessageDto;
		refresh();
	}
	public void refresh() {
		repeatTablePanel.setup(orgMessageDto.getRepeatList());

		Integer lastRowIndex = repeatTablePanel.selectLastRow();
		if(lastRowIndex == null) {
			setMessage(orgMessageDto);
			return;
		}
		setMessage(lastRowIndex);
	}

	public void setMessage(int rowIndex) {
		MessageRepeatDto messageRepeatDto = repeatTablePanel.getRow(rowIndex);
		setMessage(messageRepeatDto);
	}
	private void setMessage(MessageRepeatDto messageRepeatDto) {
		messageEditorPanel.setMessage(messageRepeatDto.getMessage());
		refreshFollowRedirectButton(messageRepeatDto.getStatus());
	}
	private void setMessage(MessageRepeatRedirectDto messageRepeatRedirectDto) {
		messageEditorPanel.setMessage(messageRepeatRedirectDto.getMessage());
		refreshFollowRedirectButton(messageRepeatRedirectDto.getStatus());
	}
	private void setMessage(MessageDto messageDto) {
		messageEditorPanel.setMessage(messageDto);
		refreshFollowRedirectButton(messageDto.getStatus());
	}
	private void setMessage(IHttpRequestResponse message) {
		messageEditorPanel.setMessage(message);
		refreshFollowRedirectButton(BurpUtil.getHelpers().analyzeResponse(message.getResponse()).getStatusCode());
	}

	public void refreshAuthSessionValueLabel() {
		SwingUtilities.invokeLater(() -> {
			authSessionValueLabel.setText(authAccountComboBox.getItemAt(authAccountComboBox.getSelectedIndex()).getSessionIdForDisplay());
		});
	}

	public void sendRequest() {
		AuthAccountDto authAccountDto = getSelectedAuthAccountDto();
		if(authAccountDto != null && authAccountDto.getSessionId() == null) {
			Controller.getInstance().fetchNewAuthSession(authAccountDto, x -> {
				sendRequestImpl(authAccountDto);
			});
			return;
		}

		sendRequestImpl(authAccountDto);
	}
	private void sendRequestImpl(AuthAccountDto authAccountDto) {
		var messageRepeatDto = Controller.getInstance().sendRepeaterRequest(messageEditorPanel.getRequest(), authAccountDto, orgMessageDto, repeatedDto -> {
			SwingUtilities.invokeLater(() -> {
				if(!orgMessageDto.getId().equals(repeatedDto.getOrgMessageId())) {
					return;
				}
				repeatTablePanel.applyResponseInfoToRow(repeatedDto);
				if(!repeatTablePanel.judgeIsSelected(repeatedDto)) {
					return;
				}
				setMessage(repeatedDto);
			});
		});

		repeatTablePanel.addRow(messageRepeatDto);
		repeatTablePanel.selectLastRow();
		setMessage(messageRepeatDto);
	}

	private void followRedirect() {
		var request = messageEditorPanel.getRequest();
		var response = messageEditorPanel.getResponse();
		var messageRepeatRedirectDto = Controller.getInstance().sendFollowRedirectRequest(request, response, orgMessageDto, redirectedDto -> {
			SwingUtilities.invokeLater(() -> {
//				if(!orgMessageDto.getId().equals(redirectedDto.getOrgMessageId())) { //TODO: impl
//					return;
//				}
				setMessage(redirectedDto);
			});
		});

		setMessage(messageRepeatRedirectDto);
	}

	private void refreshFollowRedirectButton(Short statusCode) {
		if(statusCode == null) {
			followRedirectButton.setEnabled(false);
			return;
		}
		followRedirectButton.setEnabled(statusCode / 100 == 3);
	}

	public void refreshAuthAccountsComboBox() {
		authAccountComboBox.removeAllItems();
		authAccountComboBox.addItem(new AuthAccountDto()); //dummy
		authAccountComboBox.setEnabled(false);
		authSessionRefreshButton.setEnabled(false);
		authSessionValueLabel.setText(null);

		if(!ConfigLogic.getInstance().isAuthConfigReady()) {
			return;
		}

		Controller.getInstance().getAuthAccounts().forEach(authAccount -> {
			authAccountComboBox.addItem(authAccount);
		});
		authAccountComboBox.setEnabled(authAccountComboBox.getItemCount() > 1);
	}

	public AuthAccountDto getSelectedAuthAccountDto() {
		var selectedIndex = authAccountComboBox.getSelectedIndex();
		if(selectedIndex < 1) { //dummy
			return null;
		}
		return authAccountComboBox.getItemAt(selectedIndex);
	}

	public MessageDto getOrgMessageDto() {
		return orgMessageDto;
	}

	public void clear() {
		repeatTablePanel.clear();
		messageEditorPanel.clearMessage();
		followRedirectButton.setEnabled(false);
	}

	public void initDividerLocation() {
		splitPane.setDividerLocation(Positions.DIVIDER_LOCATION_REPEATER);
	}

	@Override
	protected AbstractButton getDockoutButton() {
		return dockoutButton;
	}
	@Override
	protected String getTabName() {
		return Captions.TAB_MAIN_MESSAGE_EDITOR_REPEAT;
	}
	@Override
	protected int getTabIndex() {
		return 2;
	}
	@Override
	protected JTabbedPane getParentTabbedPane() {
		return Controller.getInstance().getMessageDetailTabbedPane();
	}

}
