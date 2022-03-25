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

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import java.awt.event.ActionListener;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;

public class ChainDefPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final int TIMES_DEFAULT = 1;

	private MessageDto messageDto;
	private Integer messageChainId;

	private MessageChainDto loadedMessageChainDto;

	private MessageChainRepeatDto breakingMessageChainRepeatDto;

	private JButton startButton;
	private JButton terminateButton;
	private JButton stepButton;

	private JSpinner timesSpinner;
	private JLabel timesCountdownLabel;

	private JFrame popupFrame;
	private JPanel nodesPanel;
	private ChainDefPresetVarsPanel presetVarsPanel;

	public ChainDefPanel(MessageDto messageDto, Integer messageChainId) {
		this.messageDto = messageDto;
		this.messageChainId = messageChainId;
		
		setLayout(new BorderLayout(0, 0));
		
		JPanel configPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) configPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(configPanel, BorderLayout.NORTH);
		
		presetVarsPanel = new ChainDefPresetVarsPanel(this);
		configPanel.add(presetVarsPanel);
		
		JPanel controlCenterPanel = new JPanel();
		configPanel.add(controlCenterPanel, BorderLayout.CENTER);
		
		startButton = new JButton(Captions.CHAIN_DEF_RUN);
		startButton.setToolTipText(Captions.CHAIN_DEF_RUN_TT);
		controlCenterPanel.add(startButton);
		startButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				start(false);
			}
		});
		
		terminateButton = new JButton(Captions.CHAIN_DEF_TERMINATE);
		terminateButton.setToolTipText(Captions.CHAIN_DEF_TERMINATE_TT);
		controlCenterPanel.add(terminateButton);
		terminateButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				terminate();
			}
		});
		
		stepButton = new JButton(Captions.CHAIN_DEF_STEP);
		stepButton.setToolTipText(Captions.CHAIN_DEF_STEP_TT);
		controlCenterPanel.add(stepButton);
		stepButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				start(true);
			}
		});
		
		JLabel timesLabel = new JLabel(" x ");
		controlCenterPanel.add(timesLabel);
		
		timesSpinner = new JSpinner();
		timesSpinner.setModel(new SpinnerNumberModel(TIMES_DEFAULT, 1, 999, 1));
		controlCenterPanel.add(timesSpinner);
		
		timesCountdownLabel = new JLabel("");
		timesCountdownLabel.setForeground(Colors.CHARACTER_HIGHLIGHT);
		controlCenterPanel.add(timesCountdownLabel);
		
		JScrollPane scrollPane = new JScrollPane();
		add(scrollPane, BorderLayout.CENTER);
		
		nodesPanel = new JPanel();
		scrollPane.setViewportView(nodesPanel);
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
				addNode(buttonPanel);
			}
		});

		return buttonPanel;
	}

	private void addNode(JPanel clickedButtonPanel) {
		var index = Arrays.asList(nodesPanel.getComponents()).indexOf(clickedButtonPanel);
		addNode(null, index);
	}
	private void addNodeTail(MessageChainNodeDto nodeDto) {
		addNode(nodeDto, nodesPanel.getComponents().length - 1);
	}
	private void addNode(MessageChainNodeDto nodeDto, int baseIndex) {
		nodesPanel.add(new ChainDefNodePanel(nodeDto, this), baseIndex + 1);
		nodesPanel.add(createAddButtonPanel(), baseIndex + 2);
		UiUtil.repaint(this);
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

	private List<ChainDefNodePanel> getChainDefNodePanels() {
		return Arrays.asList(nodesPanel.getComponents()).stream()
				.filter(component -> component instanceof ChainDefNodePanel)
				.map(chainDefNodePanel -> (ChainDefNodePanel)chainDefNodePanel)
				.collect(Collectors.toList());
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

		if(judgeIsAuthChain()) {
			runImpl(chainDefNodePanels, chainDto, Controller.getInstance().getSelectedAuthAccountOnAuthConfig(), times, isStep);
			return;
		}

		var authAccountDto = Controller.getInstance().getSelectedAuthAccountOnRepeater();
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
					chainDefNodePanels.get(index).setMessage(new HttpRequestResponseMock(breakingAppliedRequestForView, null, messageChainRepeatDto.getMessageChainDto().getNodes().get(index).getMessageDto().getMessage().getHttpService()));
					setIsCurrentNode(chainDefNodePanels, index);
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
		UiUtil.closePopup(popupFrame);
	}


	public void setPopupFrame(JFrame popupFrame) {
		this.popupFrame = popupFrame;
	}

}
