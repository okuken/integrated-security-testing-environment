package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.dto.MessageChainNodeRespDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.burp.HttpRequestResponseMock;
import okuken.iste.enums.IsteColor;
import okuken.iste.util.UiUtil;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.editor.MessageEditorsLayoutType;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;
import java.util.function.Consumer;

import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.border.LineBorder;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JCheckBox;

public class ChainDefNodePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final Dimension MESSAGE_EDITOR_PREFERRED_SIZE = new Dimension(800, 400);

	private ChainDefPanel parentChainDefPanel;

	private List<Runnable> editListeners = Lists.newArrayList();
	private List<Consumer<MessageDto>> messageSelectionChangeListeners = Lists.newArrayList();
	private List<Consumer<IHttpRequestResponse>> chainResponseListeners = Lists.newArrayList();
	private List<Consumer<Color>> colorChangeListeners = Lists.newArrayList();
	private List<Runnable> nodeRemoveListeners = Lists.newArrayList();

	private boolean isMainNode;

	private JSplitPane splitPane;

	private JComboBox<MessageDto> urlComboBox;
	private ChainDefNodeRequestParamsPanel requestParamsPanel;
	private ChainDefNodeResponseParamsPanel responseParamsPanel;

	private JPanel messageHeaderPanel;

	private JPanel messageInfoPanel;
	private JLabel messageNameLabel;

	private JPanel messageControlPanel;
	private JCheckBox breakpointCheckBox;
	private JCheckBox skipCheckBox;

	private MessageEditorPanel messageEditorPanel;

	private boolean refreshingFlag = false;

	private boolean currentNode;
	private Color panelDefaultBackgroundColor;

	public ChainDefNodePanel(MessageChainNodeDto nodeDto, ChainDefPanel parentChainDefPanel) {
		this.parentChainDefPanel = parentChainDefPanel;
		this.isMainNode = nodeDto != null && nodeDto.isMain();
		
		setLayout(new BorderLayout(0, 0));
		setBorder(isMainNode ? new LineBorder(Colors.BLOCK_BORDER_HIGHLIGHT, 2) : new LineBorder(Colors.BLOCK_BORDER));
		
		JPanel centerPanel = new JPanel(new BorderLayout(0, 0));
		add(centerPanel, BorderLayout.CENTER);
		
		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		centerPanel.add(splitPane, BorderLayout.CENTER);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBorder(null);
		UiUtil.setupScrollPaneMouseWheelDispatch(scrollPane, parentChainDefPanel.getNodesScrollPane());
		splitPane.setLeftComponent(scrollPane);
		
		JPanel panel = new JPanel(new BorderLayout(0, 0));
		scrollPane.setViewportView(panel);
		
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
					messageSelectionChangeListeners.forEach(listener -> listener.accept(getSelectedMessageDto()));
					afterEdit();
				}
			}
		});
		urlComboBox.setEnabled(!isMainNode);
		urlPanel.add(urlComboBox);
		
		requestParamsPanel = new ChainDefNodeRequestParamsPanel(this);
		FlowLayout flowLayout_1 = (FlowLayout) requestParamsPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.LEFT);
		requestParamsPanel.addEditListener(() -> afterEdit());
		mainPanel.add(requestParamsPanel);
		
		responseParamsPanel = new ChainDefNodeResponseParamsPanel(this);
		FlowLayout flowLayout_2 = (FlowLayout) responseParamsPanel.getLayout();
		flowLayout_2.setAlignment(FlowLayout.LEFT);
		responseParamsPanel.addEditListener(() -> afterEdit());
		mainPanel.add(responseParamsPanel);
		
		JPanel messagePanel = new JPanel(new BorderLayout(0, 0));
		splitPane.setRightComponent(messagePanel);
		
		messageEditorPanel = new MessageEditorPanel(null, !parentChainDefPanel.judgeIsAuthChain(), false, parentChainDefPanel.getSelectedMessageEditorsLayoutType());
		messagePanel.add(messageEditorPanel, BorderLayout.CENTER);
		messageEditorPanel.setPreferredSize(MESSAGE_EDITOR_PREFERRED_SIZE);
		
		messageHeaderPanel = new JPanel();
		messagePanel.add(messageHeaderPanel, BorderLayout.NORTH);
		messageHeaderPanel.setLayout(new BorderLayout(0, 0));
		
		messageInfoPanel = new JPanel();
		FlowLayout flowLayout_4 = (FlowLayout) messageInfoPanel.getLayout();
		flowLayout_4.setVgap(2);
		flowLayout_4.setAlignment(FlowLayout.LEFT);
		messageHeaderPanel.add(messageInfoPanel, BorderLayout.NORTH);
		
		messageNameLabel = new JLabel();
		messageInfoPanel.add(messageNameLabel);
		
		messageControlPanel = new JPanel();
		FlowLayout flowLayout_3 = (FlowLayout) messageControlPanel.getLayout();
		flowLayout_3.setVgap(2);
		flowLayout_3.setAlignment(FlowLayout.LEFT);
		messageHeaderPanel.add(messageControlPanel, BorderLayout.CENTER);
		
		breakpointCheckBox = new JCheckBox(Captions.CHAIN_DEF_NODE_MESSAGE_CHECKBOX_BREAK_POINT);
		breakpointCheckBox.setToolTipText(Captions.CHAIN_DEF_NODE_MESSAGE_CHECKBOX_BREAK_POINT_TT);
		breakpointCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				refreshBackgroundColor();
				afterEdit();
			}
		});
		messageControlPanel.add(breakpointCheckBox);
		
		skipCheckBox = new JCheckBox(Captions.CHAIN_DEF_NODE_MESSAGE_CHECKBOX_SKIP);
		skipCheckBox.setToolTipText(Captions.CHAIN_DEF_NODE_MESSAGE_CHECKBOX_SKIP_TT);
		skipCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				refreshBackgroundColor();
				afterEdit();
			}
		});
		messageControlPanel.add(skipCheckBox);
		
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
				setMessage(getSelectedMessageDto(), true);
			}
		});
		messageControlPanel.add(copyOrgButton);
		
		JButton copyMasterButton = new JButton(Captions.REPEATER_BUTTON_COPY_MASTER);
		copyMasterButton.setToolTipText(Captions.REPEATER_BUTTON_COPY_MASTER_TT);
		copyMasterButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				setMessage(getSelectedMessageDto().getMasterMessage(), false);
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
		
		JPanel nodeControlPanel = new JPanel(new GridLayout(0, 1, 0, 0));
		leftPanel.add(nodeControlPanel);
		
		JButton btnUp = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_UP);
		btnUp.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_UP_TT);
		btnUp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				upNode();
			}
		});
		nodeControlPanel.add(btnUp);

		JButton btnDown = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_DOWN);
		btnDown.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_DOWN_TT);
		btnDown.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				downNode();
			}
		});
		nodeControlPanel.add(btnDown);
		
		nodeControlPanel.add(UiUtil.createSpacer());
		
		JButton btnDelete = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_DELETE);
		btnDelete.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_DELETE_TT);
		btnDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				removeNode();
			}
		});
		btnDelete.setEnabled(!isMainNode);
		nodeControlPanel.add(btnDelete);
		
		initPanel(nodeDto);
	}

	private void initPanel(MessageChainNodeDto nodeDto) {
		refreshPanel(nodeDto, Controller.getInstance().getMessages());

		SwingUtilities.invokeLater(() -> {
			UiUtil.setOpaqueChildComponents(this, false);
			panelDefaultBackgroundColor = getBackground();
			refreshBackgroundColor();
		});
	}

	private void refreshPanel(MessageChainNodeDto nodeDto, List<MessageDto> messageDtos) {
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
			skipCheckBox.setSelected(nodeDto.isSkip());

		} finally {
			refreshingFlag = refreshingFlagBk;
		}
	}

	private void refreshMessageEditorPanel() {
		var messageDto = getSelectedMessageDto();
		messageNameLabel.setText(messageDto.toString());
		setMessage(messageDto, false);
	}

	public void changeMessageEditorsLayout(MessageEditorsLayoutType type) {
		messageEditorPanel.setupMessageEditorsLayout(type);
	}

	public void collapseSettingPanel() {
		splitPane.setDividerLocation(0);
	}
	public void expandSettingPanel() {
		splitPane.setDividerLocation(0.4);
	}

	private void upNode() {
		parentChainDefPanel.upNode(this);
		afterEdit();
	}

	private void downNode() {
		parentChainDefPanel.downNode(this);
		afterEdit();
	}

	private void removeNode() {
		parentChainDefPanel.removeNode(this);
		nodeRemoveListeners.forEach(Runnable::run);
		afterEdit();
	}

	public MessageChainNodeDto makeNodeDto() {
		//TODO: validation
		var nodeDto = new MessageChainNodeDto();
		nodeDto.setMain(isMainNode);
		nodeDto.setMessageDto(getSelectedMessageDto());
		nodeDto.setReqps(requestParamsPanel.getRows());
		nodeDto.setResps(responseParamsPanel.getRows());
		nodeDto.setBreakpoint(breakpointCheckBox.isSelected());
		nodeDto.setSkip(skipCheckBox.isSelected());
		nodeDto.setEditedRequest(messageEditorPanel.getRequest());
		return nodeDto;
	}

	public MessageDto getSelectedMessageDto() {
		return urlComboBox.getItemAt(urlComboBox.getSelectedIndex());
	}

	public byte[] getRequest() {
		return messageEditorPanel.getRequest();
	}

	public byte[] getResponse() {
		return messageEditorPanel.getResponse();
	}

	public void setMessage(IHttpRequestResponse message, boolean chainResponse) {
		messageEditorPanel.setMessage(message, true);
		requestParamsPanel.refreshAllRegexResult();
		responseParamsPanel.refreshAllRegexResult();
		if(chainResponse) {
			chainResponseListeners.forEach(listener -> listener.accept(message));
		}
	}

	private void setMessage(MessageDto messageDto, boolean keepCaretPosition) {
		messageEditorPanel.setMessage(messageDto, keepCaretPosition);
		requestParamsPanel.refreshAllRegexResult();
		responseParamsPanel.refreshAllRegexResult();
	}

	private void setResponse(byte[] response) {
		messageEditorPanel.setResponse(response);
		responseParamsPanel.refreshAllRegexResult();
	}

	void addReqp(MessageChainNodeReqpDto reqpDto) {
		requestParamsPanel.addRow(reqpDto);
	}

	void addResp(MessageChainNodeRespDto respDto) {
		responseParamsPanel.addRow(respDto);
	}

	void stopEditing() {
		requestParamsPanel.stopEditing();
		responseParamsPanel.stopEditing();
	}

	public void focusMessageEditor() {
		messageEditorPanel.focusRequest();
	}

	public void focusMessageSelector() {
		UiUtil.focus(urlComboBox);
	}

	public void setIsCurrentNode() {
		currentNode = true;
		refreshBackgroundColor();
	}
	public void clearIsCurrentNode() {
		currentNode = false;
		refreshBackgroundColor();
	}

	private void refreshBackgroundColor() {
		var color = panelDefaultBackgroundColor;
		if(skipCheckBox.isSelected()) {
			color = IsteColor.BLOCK_BACKGROUND_GRAYOUT.get();
			messageHeaderPanel.setOpaque(false);
			setBackground(color);
		} else if(currentNode) {
			color = IsteColor.BLOCK_BACKGROUND_HIGHLIGHT.get();
			messageHeaderPanel.setOpaque(true);
			messageHeaderPanel.setBackground(color);
		} else if(breakpointCheckBox.isSelected()) {
			color = IsteColor.BLOCK_BACKGROUND_HOLD.get();
			messageHeaderPanel.setOpaque(false);
			setBackground(color);
		} else {
			messageHeaderPanel.setOpaque(false);
			setBackground(color);
		}

		for(var listener: colorChangeListeners) {
			listener.accept(color);
		}

		UiUtil.repaint(this);
	}

	public boolean isMainNode() {
		return isMainNode;
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
		var repeatDto = Controller.getInstance().sendRepeaterRequest(messageEditorPanel.getRequest(), authAccountDto, orgMessageDto, repeatedDto -> {
			SwingUtilities.invokeLater(() -> {
				setResponse(repeatedDto.getMessage().getResponse());
				if(isMainNode) {
					Controller.getInstance().refreshRepeatTablePanel(orgMessageDto.getId());
				}
			});
		}, isMainNode);
		setMessage(repeatDto.getMessage(), false);
	}


	public ChainDefPanel getParentChainDefPanel() {
		return parentChainDefPanel;
	}


	private void afterEdit() {
		editListeners.forEach(Runnable::run);
	}

	void addEditListener(Runnable listener) {
		editListeners.add(listener);
	}

	void addMessageSelectionChangeListener(Consumer<MessageDto> listener) {
		messageSelectionChangeListeners.add(listener);
	}
	void addChainResponseListener(Consumer<IHttpRequestResponse> listener) {
		chainResponseListeners.add(listener);
	}
	void addColorChangeListener(Consumer<Color> listener) {
		colorChangeListeners.add(listener);
	}
	void addNodeRemoveListener(Runnable listener) {
		nodeRemoveListeners.add(listener);
	}

}
