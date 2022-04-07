package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.BoxLayout;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainRepeatDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.burp.HttpRequestResponseMock;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.UiUtil;
import okuken.iste.view.common.AuthAccountSelectorPanel;
import okuken.iste.view.message.editor.MessageEditorsLayoutType;
import okuken.iste.view.message.editor.MessageEditorsLayoutTypeSelectorPanel;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import java.awt.GridLayout;
import javax.swing.JCheckBox;

public class ChainDefPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final int TIMES_DEFAULT = 1;

	private MessageDto messageDto;
	private Integer messageChainId;

	private MessageChainDto loadedMessageChainDto;

	private MessageChainRepeatDto breakingMessageChainRepeatDto;

	private AuthAccountSelectorPanel authAccountSelectorPanel;

	private JButton startButton;
	private JButton terminateButton;
	private JButton stepButton;

	private JSpinner timesSpinner;
	private JLabel timesCountdownLabel;

	private boolean autoScrollWhenBreaking = true;

	private JFrame popupFrame;
	private JScrollPane nodesScrollPane;
	private JPanel nodesPanel;
	private ChainDefPresetVarsPanel presetVarsPanel;
	private MessageEditorsLayoutTypeSelectorPanel messageEditorsLayoutTypeSelectorPanel;

	public ChainDefPanel(MessageDto messageDto, Integer messageChainId) {
		this.messageDto = messageDto;
		this.messageChainId = messageChainId;
		
		setLayout(new BorderLayout(0, 0));
		
		JPanel headerPanel = new JPanel();
		add(headerPanel, BorderLayout.NORTH);
		headerPanel.setLayout(new BorderLayout(0, 0));
		
		presetVarsPanel = new ChainDefPresetVarsPanel(this);
		headerPanel.add(presetVarsPanel, BorderLayout.WEST);
		
		JScrollPane operationScrollPane = new JScrollPane();
		operationScrollPane.setBorder(null);
		headerPanel.add(operationScrollPane, BorderLayout.CENTER);
		
		JPanel operationPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) operationPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		operationScrollPane.setViewportView(operationPanel);
		
		JPanel operationMainPanel = new JPanel();
		operationMainPanel.setLayout(new GridLayout(0, 1, 0, 0));
		operationPanel.add(operationMainPanel);
		
		authAccountSelectorPanel = new AuthAccountSelectorPanel(judgeIsAuthChain());
		FlowLayout flowLayout_1 = (FlowLayout) authAccountSelectorPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.LEFT);
		authAccountSelectorPanel.refreshComboBox();
		operationMainPanel.add(authAccountSelectorPanel);
		
		JPanel operationCenterPanel = new JPanel();
		FlowLayout flowLayout_2 = (FlowLayout) operationCenterPanel.getLayout();
		flowLayout_2.setAlignment(FlowLayout.LEFT);
		operationMainPanel.add(operationCenterPanel);
		
		startButton = new JButton(Captions.CHAIN_DEF_RUN);
		startButton.setToolTipText(Captions.CHAIN_DEF_RUN_TT);
		startButton.setMnemonic(KeyEvent.VK_S);
		operationCenterPanel.add(startButton);
		startButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				start(false);
			}
		});
		
		terminateButton = new JButton(Captions.CHAIN_DEF_TERMINATE);
		terminateButton.setToolTipText(Captions.CHAIN_DEF_TERMINATE_TT);
		terminateButton.setMnemonic(KeyEvent.VK_T);
		operationCenterPanel.add(terminateButton);
		terminateButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				terminate();
			}
		});
		
		stepButton = new JButton(Captions.CHAIN_DEF_STEP);
		stepButton.setToolTipText(Captions.CHAIN_DEF_STEP_TT);
		stepButton.setMnemonic(KeyEvent.VK_X);
		operationCenterPanel.add(stepButton);
		stepButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				start(true);
			}
		});
		
		JLabel timesLabel = new JLabel(" x ");
		operationCenterPanel.add(timesLabel);
		
		timesSpinner = new JSpinner();
		timesSpinner.setModel(new SpinnerNumberModel(TIMES_DEFAULT, 1, 999, 1));
		operationCenterPanel.add(timesSpinner);
		
		timesCountdownLabel = new JLabel("");
		timesCountdownLabel.setForeground(Colors.CHARACTER_HIGHLIGHT);
		operationCenterPanel.add(timesCountdownLabel);
		
		JPanel configPanel = new JPanel();
		headerPanel.add(configPanel, BorderLayout.EAST);
		
		JPanel configMainPanel = new JPanel();
		configPanel.add(configMainPanel);
		configMainPanel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel layoutControlPanel = new JPanel();
		FlowLayout flowLayout_4 = (FlowLayout) layoutControlPanel.getLayout();
		flowLayout_4.setVgap(0);
		configMainPanel.add(layoutControlPanel);
		
		JButton collapseButton = new JButton(Captions.CHAIN_DEF_SPLIT_COLLAPSE);
		collapseButton.setToolTipText(Captions.CHAIN_DEF_SPLIT_COLLAPSE_TT);
		collapseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				getChainDefNodePanels().stream().forEach(ChainDefNodePanel::collapseSettingPanel);
			}
		});
		layoutControlPanel.add(collapseButton);
		
		JButton expandButton = new JButton(Captions.CHAIN_DEF_SPLIT_EXPAND);
		expandButton.setToolTipText(Captions.CHAIN_DEF_SPLIT_EXPAND_TT);
		expandButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				getChainDefNodePanels().stream().forEach(ChainDefNodePanel::expandSettingPanel);
			}
		});
		layoutControlPanel.add(expandButton);
		
		layoutControlPanel.add(UiUtil.createSpacer());
		
		messageEditorsLayoutTypeSelectorPanel = new MessageEditorsLayoutTypeSelectorPanel(type -> {
			getChainDefNodePanels().stream().forEach(nodePanel -> nodePanel.changeMessageEditorsLayout(type));
		});
		FlowLayout flowLayout_5 = (FlowLayout) messageEditorsLayoutTypeSelectorPanel.getLayout();
		flowLayout_5.setHgap(0);
		layoutControlPanel.add(messageEditorsLayoutTypeSelectorPanel);
		
		JPanel scrollControlPanel = new JPanel();
		FlowLayout flowLayout_3 = (FlowLayout) scrollControlPanel.getLayout();
		flowLayout_3.setAlignment(FlowLayout.RIGHT);
		configMainPanel.add(scrollControlPanel);
		
		JCheckBox autoScrollCheckBox = new JCheckBox(Captions.CHAIN_DEF_AUTO_SCROLL);
		autoScrollCheckBox.setToolTipText(Captions.CHAIN_DEF_AUTO_SCROLL_TT);
		autoScrollCheckBox.setSelected(autoScrollWhenBreaking);
		autoScrollCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				autoScrollWhenBreaking = autoScrollCheckBox.isSelected();
			}
		});
		scrollControlPanel.add(autoScrollCheckBox);
		
		nodesScrollPane = new JScrollPane();
		add(nodesScrollPane, BorderLayout.CENTER);
		
		nodesPanel = new JPanel();
		nodesScrollPane.setViewportView(nodesPanel);
		nodesPanel.setLayout(new BoxLayout(nodesPanel, BoxLayout.PAGE_AXIS));
		
		JPanel controlPanel = new JPanel();
		add(controlPanel, BorderLayout.SOUTH);
		controlPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel controlLeftPanel = new JPanel();
		controlPanel.add(controlLeftPanel, BorderLayout.WEST);
		
		JButton cancelButton = new JButton(Captions.CHAIN_DEF_CANCEL);
		controlLeftPanel.add(cancelButton);
		cancelButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				cancel();
			}
		});
		
		JPanel controlRightPanel = new JPanel();
		controlPanel.add(controlRightPanel, BorderLayout.EAST);
		
		JLabel saveMessageLabel = UiUtil.createTemporaryMessageArea();
		controlRightPanel.add(saveMessageLabel);
		
		JButton saveButton = new JButton(Captions.CHAIN_DEF_SAVE);
		controlRightPanel.add(saveButton);
		saveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				save();
				UiUtil.showTemporaryMessage(saveMessageLabel, Captions.MESSAGE_SAVED);
			}
		});
		
		init();
	}

	private void init() {
		nodesPanel.add(createAddButtonPanel());
		if(messageChainId == null) {
			var nodeDto = new MessageChainNodeDto();
			nodeDto.setMessageDto(messageDto);
			nodeDto.setMain(true);
			addNodeTail(nodeDto);
			return;
		}

		loadedMessageChainDto = Controller.getInstance().loadMessageChain(messageChainId);
		loadedMessageChainDto.getNodes().stream().forEach(nodeDto -> {
			addNodeTail(nodeDto);
		});

		presetVarsPanel.refreshPanel();
		refreshControlsState();

		var mainNodePanel = getMainChainDefNodePanel();
		if(mainNodePanel.isPresent()) {
			SwingUtilities.invokeLater(() -> {
				focusNode(mainNodePanel.get(), true);
			});
		}
	}

	private void refreshControlsState() {
		var isRunningOrBreaking = (breakingMessageChainRepeatDto != null);
		var isBreaking = isRunningOrBreaking && breakingMessageChainRepeatDto.isBreaking();
		var isRunning = (isRunningOrBreaking && !isBreaking);

		startButton.setEnabled(!isRunning);
		stepButton.setEnabled(!isRunning);
		terminateButton.setEnabled(isRunningOrBreaking);
	}

	MessageChainDto getLoadedMessageChainDto() {
		return loadedMessageChainDto;
	}

	private JPanel createAddButtonPanel() {
		var buttonPanel = new JPanel();
		((FlowLayout) buttonPanel.getLayout()).setAlignment(FlowLayout.LEFT);

		var addButton = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_ADD);
		addButton.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_ADD_TT);
		buttonPanel.add(addButton);
		addButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var nodePanel = addNode(buttonPanel);
				SwingUtilities.invokeLater(() -> {
					focusNode(nodePanel, false);
				});
			}
		});

		return buttonPanel;
	}

	private ChainDefNodePanel addNode(JPanel clickedButtonPanel) {
		var index = Arrays.asList(nodesPanel.getComponents()).indexOf(clickedButtonPanel);
		return addNode(null, index);
	}
	private void addNodeTail(MessageChainNodeDto nodeDto) {
		addNode(nodeDto, nodesPanel.getComponents().length - 1);
	}
	private ChainDefNodePanel addNode(MessageChainNodeDto nodeDto, int baseIndex) {
		var nodePanel = new ChainDefNodePanel(nodeDto, this);
		nodesPanel.add(nodePanel, baseIndex + 1);
		nodesPanel.add(createAddButtonPanel(), baseIndex + 2);
		UiUtil.repaint(this);
		return nodePanel;
	}

	void removeNode(JPanel clickedNodePanel) {
		var index = Arrays.asList(nodesPanel.getComponents()).indexOf(clickedNodePanel);
		nodesPanel.remove(index); // nodePanel
		nodesPanel.remove(index); // addButtonPanel
		UiUtil.repaint(this);
	}

	private void setIsCurrentNode(List<ChainDefNodePanel> chainDefNodePanels, Integer index) {
		chainDefNodePanels.forEach(e -> e.clearIsCurrentNode());
		if(index != null) {
			chainDefNodePanels.get(index).setIsCurrentNode();
		}
	}

	private void focusNode(ChainDefNodePanel chainDefNodePanel, boolean focusMessageEditor) {
		focusNode(chainDefNodePanel, focusMessageEditor, false);
	}
	private void focusNode(ChainDefNodePanel chainDefNodePanel, boolean focusMessageEditor, boolean forBreaking) {
		if(focusMessageEditor) {
			chainDefNodePanel.focusMessageEditor();
		} else {
			chainDefNodePanel.focusMessageSelector();
		}

		if(!forBreaking || autoScrollWhenBreaking) {
			UiUtil.scrollFor(chainDefNodePanel, nodesScrollPane);
		}
	}

	AuthAccountDto getSelectedAuthAccountDto() {
		return authAccountSelectorPanel.getSelectedAuthAccountDto();
	}

	MessageEditorsLayoutType getSelectedMessageEditorsLayoutType() {
		return messageEditorsLayoutTypeSelectorPanel.getSelectedMessageEditorsLayoutType();
	}

	JScrollPane getNodesScrollPane() {
		return nodesScrollPane;
	}

	private List<ChainDefNodePanel> getChainDefNodePanels() {
		return Arrays.asList(nodesPanel.getComponents()).stream()
				.filter(component -> component instanceof ChainDefNodePanel)
				.map(chainDefNodePanel -> (ChainDefNodePanel)chainDefNodePanel)
				.collect(Collectors.toList());
	}

	private Optional<ChainDefNodePanel> getMainChainDefNodePanel() {
		return getChainDefNodePanels().stream().filter(ChainDefNodePanel::isMainNode).findFirst();
	}

	private MessageChainDto makeChainDto() {
		var chainDto = new MessageChainDto();

		chainDto.setId(messageChainId);
		chainDto.setNodes(
			Arrays.asList(nodesPanel.getComponents()).stream()
				.filter(component -> component instanceof ChainDefNodePanel)
				.map(nodePanel -> ((ChainDefNodePanel)nodePanel).makeNodeDto())
				.collect(Collectors.toList()));
		chainDto.setPresetVars(presetVarsPanel.getRows());
		chainDto.setMessageId(messageDto != null ? messageDto.getId() : null);

		return chainDto;
	}

	private void start(boolean isStep) {
		startButton.setEnabled(false); //prevent double-click
		stepButton.setEnabled(false);

		if(breakingMessageChainRepeatDto != null) {
			resume(isStep);
		} else {
			run(isStep);
		}
		refreshControlsState();
	}

	private void run(boolean isStep) {
		var chainDefNodePanels = getChainDefNodePanels();
		if(chainDefNodePanels.isEmpty()) {
			return;
		}

		var chainDto = makeChainDto();
		var times = getTimes();

		var authAccountDto = authAccountSelectorPanel.getSelectedAuthAccountDto();
		if(judgeIsAuthChain()) {
			runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
			return;
		}

		if(authAccountDto != null && authAccountDto.isSessionIdsEmpty()) {
			Controller.getInstance().fetchNewAuthSession(authAccountDto, x -> {
				runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
			});
			return;
		}
		runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
	}

	private void resume(boolean isStep) {
		var chainDefNodePanels = getChainDefNodePanels();
		var chainDto = makeChainDto();
		var times = Integer.parseInt(timesCountdownLabel.getText());

		runImpl(chainDefNodePanels, chainDto, null, times, isStep);
	}

	private void runImpl(List<ChainDefNodePanel> chainDefNodePanels, MessageChainDto messageChainDto, AuthAccountDto authAccountDto, int times, boolean isStep) {
		SwingUtilities.invokeLater(() -> {
			timesCountdownLabel.setText(Integer.toString(times));
		});

		if(isStep) {
			if(breakingMessageChainRepeatDto != null) {
				var nextIndex = breakingMessageChainRepeatDto.getCurrentIndex() + 1;
				if(nextIndex < messageChainDto.getNodes().size()) {
					messageChainDto.getNodes().get(nextIndex).setBreakpoint(true);
				}
			} else {
				messageChainDto.getNodes().get(0).setBreakpoint(true);
			}
		}

		var needSaveHistory = !judgeIsAuthChain();
		breakingMessageChainRepeatDto = Controller.getInstance().sendMessageChain(messageChainDto, authAccountDto, (messageChainRepeatDto, index) -> {
			if(messageChainRepeatDto.isForceTerminate()) {
				SwingUtilities.invokeLater(() -> {
					timesCountdownLabel.setText(Captions.CHAIN_DEF_RUN_TERMINATE_FORCE + " (" + times + ")");
					refreshControlsState();
				});
				return;
			}
			if(messageChainRepeatDto.isBreaking()) {
				var breakingAppliedRequestForView = messageChainRepeatDto.getBreakingAppliedRequestForView();
				SwingUtilities.invokeLater(() -> {
					var chainDefNodePanel = chainDefNodePanels.get(index);
					chainDefNodePanel.setMessage(new HttpRequestResponseMock(breakingAppliedRequestForView, null, messageChainRepeatDto.getMessageChainDto().getNodes().get(index).getMessageDto().getMessage().getHttpService()));
					setIsCurrentNode(chainDefNodePanels, index);
					focusNode(chainDefNodePanel, true, true);
					refreshControlsState();
				});
				return;
			}

			SwingUtilities.invokeLater(() -> {
				chainDefNodePanels.get(index).setMessage(messageChainRepeatDto.getMessageRepeatDtos().get(index).getMessage());
				setIsCurrentNode(chainDefNodePanels, null);

				if(messageChainRepeatDto.getMessageChainDto().getNodes().get(index).isMain() && needSaveHistory) {
					Controller.getInstance().refreshRepeatTablePanel(messageChainDto.getMainNode().get().getMessageDto().getId()); //TODO:improve...
				}
			});

			var nextIndex = index + 1;
			if(nextIndex >= chainDefNodePanels.size()) { //case: last node
				breakingMessageChainRepeatDto = null;
				if(times - 1 > 0) {
					runImpl(chainDefNodePanels, messageChainDto, authAccountDto, times - 1, isStep); //recursive
				} else {
					SwingUtilities.invokeLater(() -> {
						refreshControlsState();
						timesCountdownLabel.setText(Captions.CHAIN_DEF_RUN_DONE);
					});
				}
			}

		}, judgeIsAuthChain(), needSaveHistory, breakingMessageChainRepeatDto);
	}

	private void terminate() {
		if(breakingMessageChainRepeatDto != null) {
			breakingMessageChainRepeatDto.setForceTerminate(true);
			breakingMessageChainRepeatDto = null;
		}
		setIsCurrentNode(getChainDefNodePanels(), null);
		refreshControlsState();
		timesCountdownLabel.setText("");
	}

	private int getTimes() {
		try {
			timesSpinner.commitEdit();
		} catch (ParseException e) {
			return TIMES_DEFAULT; //case: not satisfy the SpinnerNumberModel
		}

		return (Integer)timesSpinner.getValue();
	}

	private Boolean isAuthChain;
	public boolean judgeIsAuthChain() {
		if(isAuthChain == null) {
			isAuthChain = ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainId().equals(messageChainId);
		}
		return isAuthChain;
	}

	private void save() {
		var messageChainDto = makeChainDto();
		Controller.getInstance().saveMessageChain(messageChainDto, judgeIsAuthChain());
		messageChainId = messageChainDto.getId();
	}

	public void cancel() {
		authAccountSelectorPanel.unloaded();
		UiUtil.closePopup(popupFrame);
	}


	public void setPopupFrame(JFrame popupFrame) {
		this.popupFrame = popupFrame;
	}

}
