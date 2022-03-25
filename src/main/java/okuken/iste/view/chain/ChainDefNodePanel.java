package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.burp.HttpRequestResponseMock;
import okuken.iste.util.UiUtil;
import okuken.iste.view.message.editor.MessageEditorPanel;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.border.LineBorder;

import burp.IHttpRequestResponse;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JCheckBox;

public class ChainDefNodePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final Dimension MESSAGE_EDITOR_PREFERRED_SIZE = new Dimension(800, 400);

	private ChainDefPanel parentChainDefPanel;

	private boolean isMainNode;

	private JComboBox<MessageDto> urlComboBox;
	private ChainDefNodeRequestParamsPanel requestParamsPanel;
	private ChainDefNodeResponseParamsPanel responseParamsPanel;

	private JPanel messageControlPanel;
	private JCheckBox breakpointCheckBox;

	private MessageEditorPanel messageEditorPanel;

	private boolean refreshingFlag = false;

	public ChainDefNodePanel(MessageChainNodeDto nodeDto, ChainDefPanel parentChainDefPanel) {
		this.parentChainDefPanel = parentChainDefPanel;
		this.isMainNode = nodeDto != null && nodeDto.isMain();
		
		setLayout(new BorderLayout(0, 0));
		setBorder(new LineBorder(Colors.BLOCK_BORDER));
		
		JPanel centerPanel = new JPanel(new BorderLayout(0, 0));
		add(centerPanel, BorderLayout.CENTER);
		
		JPanel panel = new JPanel(new BorderLayout(0, 0));
		centerPanel.add(panel, BorderLayout.WEST);
		
		JPanel mainPanel = new JPanel();
		panel.add(mainPanel, BorderLayout.NORTH);
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.PAGE_AXIS));
		
		JPanel urlPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) urlPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		mainPanel.add(urlPanel);
		
		urlComboBox = new JComboBox<MessageDto>();
		urlComboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if(!refreshingFlag && e.getStateChange() == ItemEvent.SELECTED) {
					refreshMessageEditorPanel();
				}
			}
		});
		urlComboBox.setEnabled(!isMainNode);
		urlPanel.add(urlComboBox);
		
		requestParamsPanel = new ChainDefNodeRequestParamsPanel(this);
		FlowLayout flowLayout_1 = (FlowLayout) requestParamsPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.LEFT);
		mainPanel.add(requestParamsPanel);
		
		responseParamsPanel = new ChainDefNodeResponseParamsPanel();
		FlowLayout flowLayout_2 = (FlowLayout) responseParamsPanel.getLayout();
		flowLayout_2.setAlignment(FlowLayout.LEFT);
		mainPanel.add(responseParamsPanel);
		
		JPanel messagePanel = new JPanel(new BorderLayout(0, 0));
		centerPanel.add(messagePanel, BorderLayout.CENTER);
		
		messageEditorPanel = new MessageEditorPanel(null, !parentChainDefPanel.judgeIsAuthChain(), false, true);
		messagePanel.add(messageEditorPanel, BorderLayout.CENTER);
		messageEditorPanel.setPreferredSize(MESSAGE_EDITOR_PREFERRED_SIZE);
		
		messageControlPanel = new JPanel();
		FlowLayout flowLayout_3 = (FlowLayout) messageControlPanel.getLayout();
		flowLayout_3.setAlignment(FlowLayout.LEFT);
		messagePanel.add(messageControlPanel, BorderLayout.NORTH);
		
		breakpointCheckBox = new JCheckBox(Captions.CHAIN_DEF_NODE_MESSAGE_CHECKBOX_BREAK_POINT);
		messageControlPanel.add(breakpointCheckBox);
		
		messageControlPanel.add(UiUtil.createSpacer());
		
		JButton btnSend = new JButton(Captions.CHAIN_DEF_NODE_MESSAGE_BUTTON_SEND);
		btnSend.setToolTipText(Captions.CHAIN_DEF_NODE_MESSAGE_BUTTON_SEND_TT);
		btnSend.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				sendRequest(UiUtil.judgeIsForceRefresh(e));
			}
		});
		messageControlPanel.add(btnSend);
		
		JButton copyOrgButton = new JButton(Captions.REPEATER_BUTTON_COPY_ORG);
		copyOrgButton.setToolTipText(Captions.REPEATER_BUTTON_COPY_ORG_TT);
		copyOrgButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.clearMessage();
				messageEditorPanel.setMessage(getSelectedMessageDto());
			}
		});
		messageControlPanel.add(copyOrgButton);
		
		JButton copyMasterButton = new JButton(Captions.REPEATER_BUTTON_COPY_MASTER);
		copyMasterButton.setToolTipText(Captions.REPEATER_BUTTON_COPY_MASTER_TT);
		copyMasterButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				messageEditorPanel.clearMessage();
				messageEditorPanel.setMessage(getSelectedMessageDto().getMasterMessage());
			}
		});
		messageControlPanel.add(copyMasterButton);
		
		messageControlPanel.add(UiUtil.createSpacer());
		
		JLabel saveAsMasterMessageLabel = UiUtil.createTemporaryMessageArea();
		JButton saveAsMasterButton = new JButton(Captions.REPEATER_BUTTON_SAVE_AS_MASTER);
		saveAsMasterButton.setToolTipText(Captions.REPEATER_BUTTON_SAVE_AS_MASTER_TT);
		saveAsMasterButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var orgMessageDto = getSelectedMessageDto();
				orgMessageDto.setRepeatMasterMessage(new HttpRequestResponseMock(
						messageEditorPanel.getRequest(),
						messageEditorPanel.getResponse(),
						orgMessageDto.getMessage().getHttpService()));
				Controller.getInstance().saveRepeatMaster(orgMessageDto);
				UiUtil.showTemporaryMessage(saveAsMasterMessageLabel, Captions.MESSAGE_SAVED);
			}
		});
		messageControlPanel.add(saveAsMasterButton);
		messageControlPanel.add(saveAsMasterMessageLabel);
		
		JPanel leftPanel = new JPanel();
		add(leftPanel, BorderLayout.WEST);
		
		JButton btnDelete = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_DELETE);
		btnDelete.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_DELETE_TT);
		btnDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				removeNode();
			}
		});
		btnDelete.setEnabled(!isMainNode);
		leftPanel.add(btnDelete);
		
		initPanel(nodeDto);
	}

	private void initPanel(MessageChainNodeDto nodeDto) {
		refreshPanel(nodeDto, Controller.getInstance().getMessages());
	}

	public void refreshPanel(MessageChainNodeDto nodeDto, List<MessageDto> messageDtos) {
		var refreshingFlagBk = refreshingFlag;
		refreshingFlag = true;
		try {
			urlComboBox.removeAllItems();
			urlComboBox.setMaximumRowCount(Sizes.MAX_ROW_COUNT_COMBOBOX);
			messageDtos.forEach(messageDto -> {
				urlComboBox.addItem(messageDto);
			});

			if(nodeDto == null) {
				refreshMessageEditorPanel();
				return;
			}

			urlComboBox.setSelectedItem(messageDtos.stream().filter(messageDto -> messageDto.getId().equals(nodeDto.getMessageDto().getId())).findFirst().get());
			refreshMessageEditorPanel();

			nodeDto.getReqps().stream().forEach(reqpDto -> {
				requestParamsPanel.addRow(reqpDto);
			});
			nodeDto.getResps().stream().forEach(respDto -> {
				responseParamsPanel.addRow(respDto);
			});

			breakpointCheckBox.setSelected(nodeDto.isBreakpoint());

		} finally {
			refreshingFlag = refreshingFlagBk;
		}
	}

	private void refreshMessageEditorPanel() {
		messageEditorPanel.setMessage(getSelectedMessageDto());
	}

	private void removeNode() {
		parentChainDefPanel.removeNode(this);
	}

	public MessageChainNodeDto makeNodeDto() {
		//TODO: validation
		var nodeDto = new MessageChainNodeDto();
		nodeDto.setMain(isMainNode);
		nodeDto.setMessageDto(getSelectedMessageDto());
		nodeDto.setReqps(requestParamsPanel.getRows());
		nodeDto.setResps(responseParamsPanel.getRows());
		nodeDto.setBreakpoint(breakpointCheckBox.isSelected());
		nodeDto.setEditedRequest(messageEditorPanel.getRequest());
		return nodeDto;
	}

	private MessageDto getSelectedMessageDto() {
		return urlComboBox.getItemAt(urlComboBox.getSelectedIndex());
	}

	public void clearMessage() {
		messageEditorPanel.clearMessage();
	}
	public void setMessage(IHttpRequestResponse message) {
		messageEditorPanel.setMessage(message);
	}

	private Color messageControlPanelDefaultBackgroundColor;
	public void setIsCurrentNode() {
		if(messageControlPanelDefaultBackgroundColor == null) {
			messageControlPanelDefaultBackgroundColor = messageControlPanel.getBackground();
		}
		messageControlPanel.setBackground(Colors.BLOCK_BACKGROUND_HIGHLIGHT);
	}
	public void clearIsCurrentNode() {
		if(messageControlPanelDefaultBackgroundColor != null) {
			messageControlPanel.setBackground(messageControlPanelDefaultBackgroundColor);
		}
	}


	private void sendRequest(boolean forceAuthSessionRefresh) {
		AuthAccountDto authAccountDto = parentChainDefPanel.getSelectedAuthAccountDto();
		if(authAccountDto != null && (forceAuthSessionRefresh || authAccountDto.isSessionIdsEmpty())) {
			Controller.getInstance().fetchNewAuthSession(authAccountDto, x -> {
				sendRequestImpl(authAccountDto);
			});
			return;
		}

		sendRequestImpl(authAccountDto);
	}
	private void sendRequestImpl(AuthAccountDto authAccountDto) {
		var orgMessageDto = getSelectedMessageDto();
		Controller.getInstance().sendRepeaterRequest(messageEditorPanel.getRequest(), authAccountDto, orgMessageDto, repeatedDto -> {
			SwingUtilities.invokeLater(() -> {
				messageEditorPanel.setResponse(repeatedDto.getMessage().getResponse());
				if(isMainNode) {
					Controller.getInstance().refreshRepeatTablePanel(orgMessageDto.getId());
				}
			});
		}, isMainNode);
	}


	public ChainDefPanel getParentChainDefPanel() {
		return parentChainDefPanel;
	}

}
