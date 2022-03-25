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
import java.awt.event.KeyEvent;
import java.util.List;
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
		
		repeatTablePanel = new RepeatTablePanel(this);
		headerPanel.add(repeatTablePanel, BorderLayout.CENTER);
		
		JPanel controlPanel = new JPanel();
		headerPanel.add(controlPanel, BorderLayout.SOUTH);
		controlPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel controlLeftPanel = new JPanel();
		controlPanel.add(controlLeftPanel, BorderLayout.WEST);
		
		JButton sendButton = new JButton(Captions.REPEATER_BUTTON_SEND);
		sendButton.setToolTipText(Captions.REPEATER_BUTTON_SEND_TT);
		sendButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sendRequest(UiUtil.judgeIsForceRefresh(e));
			}
		});
		sendButton.setMnemonic(KeyEvent.VK_S);
		controlLeftPanel.add(sendButton);
		
		authAccountComboBox = new JComboBox<AuthAccountDto>();
		authAccountComboBox.setToolTipText(Captions.REPEATER_COMBOBOX_ACCOUNT_TT);
		authAccountComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				authSessionRefreshButton.setEnabled(authAccountComboBox.getSelectedIndex() > 0);
				refreshAuthSessionValueLabelImpl();
			}
		});
		controlLeftPanel.add(authAccountComboBox);
		
		authSessionRefreshButton = new JButton(Captions.REPEATER_BUTTON_AUTH_SESSION_REFRESH);
		authSessionRefreshButton.setToolTipText(Captions.REPEATER_BUTTON_AUTH_SESSION_REFRESH_TT);
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
		copyOrgButton.setToolTipText(Captions.REPEATER_BUTTON_COPY_ORG_TT);
		copyOrgButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.clearMessage();
				setMessage(orgMessageDto);
			}
		});
		controlLeftPanel.add(copyOrgButton);
		
		JButton copyMasterButton = new JButton(Captions.REPEATER_BUTTON_COPY_MASTER);
		copyMasterButton.setToolTipText(Captions.REPEATER_BUTTON_COPY_MASTER_TT);
		copyMasterButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.clearMessage();
				setMessage(getMasterMessage());
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
		saveAsMasterButton.setToolTipText(Captions.REPEATER_BUTTON_SAVE_AS_MASTER_TT);
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
		chainButton.setToolTipText(Captions.REPEATER_BUTTON_CHAIN_TT);
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
	private void setResponse(MessageRepeatDto messageRepeatDto) {
		messageEditorPanel.setResponse(messageRepeatDto.getMessage().getResponse());
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
			refreshAuthSessionValueLabelImpl();
		});
	}
	private void refreshAuthSessionValueLabelImpl() {
		var authAccountDto = getSelectedAuthAccountDto();
		if(authAccountDto == null) {
			authSessionValueLabel.setText(null);
			authSessionValueLabel.setComponentPopupMenu(null);
			return;
		}

		authSessionValueLabel.setText(authAccountDto.getSessionIdForDisplay());
		if(!authAccountDto.isSessionIdsEmpty()) {
			authSessionValueLabel.setComponentPopupMenu(
				UiUtil.createCopyPopupMenu(authAccountDto.getSessionIds().subList(0, ConfigLogic.getInstance().getAuthConfig().getAuthApplyConfigDtos().size())));
		}
	}

	public void sendRequest(boolean forceAuthSessionRefresh) {
		AuthAccountDto authAccountDto = getSelectedAuthAccountDto();
		if(authAccountDto != null && (forceAuthSessionRefresh || authAccountDto.isSessionIdsEmpty())) {
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
				setResponse(repeatedDto);
			});
		});

		repeatTablePanel.addRow(messageRepeatDto);
		repeatTablePanel.selectLastRow();
		setResponse(messageRepeatDto); //not set request to prevent focus out of messageEditor
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
		var bkSelectedIndex = authAccountComboBox.getSelectedIndex();

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

		if(bkSelectedIndex > 0 && bkSelectedIndex < authAccountComboBox.getItemCount()) {
			authAccountComboBox.setSelectedIndex(bkSelectedIndex);
		}
	}

	public AuthAccountDto getSelectedAuthAccountDto() {
		var selectedIndex = authAccountComboBox.getSelectedIndex();
		if(selectedIndex < 1) { //dummy
			return null;
		}
		return authAccountComboBox.getItemAt(selectedIndex);
	}

	public List<MessageRepeatDto> getSelectedMessageRepeatDtos() {
		return repeatTablePanel.getSelectedRows();
	}

	public MessageDto getOrgMessageDto() {
		return orgMessageDto;
	}

	public IHttpRequestResponse getMasterMessage() {
		return orgMessageDto.getMasterMessage();
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
