package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.BoxLayout;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.HttpCookieDto;
import okuken.iste.dto.HttpRequestParameterDto;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.dto.MessageChainNodeRespDto;
import okuken.iste.dto.MessageChainRepeatDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.ResponseParameterType;
import okuken.iste.enums.SourceType;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpApiUtil;
import okuken.iste.util.MessageUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.util.ValidationUtil;
import okuken.iste.view.AbstractAction;
import okuken.iste.view.common.AuthAccountSelectorPanel;
import okuken.iste.view.common.MultipleSelectorPanel;
import okuken.iste.view.common.VerticalFlowPanel;
import okuken.iste.view.message.editor.MessageEditorsLayoutType;
import okuken.iste.view.message.editor.MessageEditorsLayoutTypeSelectorPanel;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
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
	private String messageChainPrcDate;

	private MessageChainDto loadedMessageChainDto;

	private MessageChainRepeatDto breakingMessageChainRepeatDto;

	private AuthAccountSelectorPanel authAccountSelectorPanel;

	private JButton startButton;
	private JButton terminateButton;
	private JButton stepButton;

	private JSpinner timesSpinner;
	private JLabel timesCountdownLabel;

	private JLabel startMessageLabel;
	private JLabel saveMessageLabel;

	private JButton saveButton;

	private boolean autoScrollWhenBreaking = true;

	private JFrame popupFrame;
	private JScrollPane nodesScrollPane;
	private JPanel nodesPanel;
	private JPanel nodeLabelsPanel; 
	private ChainDefPresetVarsPanel presetVarsPanel;
	private MessageEditorsLayoutTypeSelectorPanel messageEditorsLayoutTypeSelectorPanel;
	private JPanel controlPanel;

	private boolean autoStartMode;

	public ChainDefPanel(MessageDto messageDto, Integer messageChainId) {
		this(messageDto, messageChainId, Lists.newArrayList(messageDto), false);
	}
	@SuppressWarnings("serial")
	public ChainDefPanel(MessageDto messageDto, Integer messageChainId, List<MessageDto> elementMessageDtos, boolean clean) {
		this.messageDto = messageDto;
		this.messageChainId = messageChainId;
		
		setLayout(new BorderLayout(0, 0));
		
		JPanel headerPanel = new JPanel();
		add(headerPanel, BorderLayout.NORTH);
		headerPanel.setLayout(new BorderLayout(0, 0));
		
		presetVarsPanel = new ChainDefPresetVarsPanel(this);
		presetVarsPanel.addEditListener(() -> afterEdit());
		headerPanel.add(presetVarsPanel, BorderLayout.WEST);
		
		JScrollPane operationScrollPane = new JScrollPane();
		operationScrollPane.setBorder(null);
		headerPanel.add(operationScrollPane, BorderLayout.CENTER);
		
		JPanel operationBasePanel = new JPanel();
		operationBasePanel.setLayout(new BorderLayout(0, 0));
		operationScrollPane.setViewportView(operationBasePanel);
		
		JPanel operationPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) operationPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		operationBasePanel.add(operationPanel, BorderLayout.CENTER);
		
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
		
		stepButton = new JButton(Captions.CHAIN_DEF_STEP);
		stepButton.setToolTipText(Captions.CHAIN_DEF_STEP_TT);
		stepButton.setMnemonic(KeyEvent.VK_F);
		operationCenterPanel.add(stepButton);
		stepButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				start(true, UiUtil.judgeIsForceRefresh(e));
			}
		});
		
		startButton = new JButton(Captions.CHAIN_DEF_RUN);
		startButton.setToolTipText(Captions.CHAIN_DEF_RUN_TT);
		startButton.setMnemonic(KeyEvent.VK_S);
		operationCenterPanel.add(startButton);
		startButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				start(false, UiUtil.judgeIsForceRefresh(e));
			}
		});
		
		terminateButton = new JButton(Captions.CHAIN_DEF_TERMINATE);
		terminateButton.setToolTipText(Captions.CHAIN_DEF_TERMINATE_TT);
		terminateButton.setMnemonic(KeyEvent.VK_T);
		operationCenterPanel.add(terminateButton);
		terminateButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				terminate();
			}
		});
		
		operationCenterPanel.add(UiUtil.createSpacer());
		
		JLabel timesLabel = new JLabel(" x ");
		operationCenterPanel.add(timesLabel);
		
		timesSpinner = new JSpinner();
		timesSpinner.setModel(new SpinnerNumberModel(TIMES_DEFAULT, 1, 999, 1));
		operationCenterPanel.add(timesSpinner);
		
		timesCountdownLabel = new JLabel("");
		timesCountdownLabel.setForeground(Colors.CHARACTER_HIGHLIGHT);
		operationCenterPanel.add(timesCountdownLabel);
		
		startMessageLabel = UiUtil.createTemporaryMessageArea();
		operationPanel.add(startMessageLabel);
		
		nodeLabelsPanel = new JPanel();
		FlowLayout flowLayout_6 = (FlowLayout) nodeLabelsPanel.getLayout();
		flowLayout_6.setAlignment(FlowLayout.LEFT);
		flowLayout_6.setHgap(10);
		operationBasePanel.add(nodeLabelsPanel, BorderLayout.SOUTH);
		
		JPanel configPanel = new JPanel();
		headerPanel.add(configPanel, BorderLayout.EAST);
		
		JPanel semiAutoSettingPanel = new JPanel(new BorderLayout(0, 0));
		semiAutoSettingPanel.setBorder(new LineBorder(Colors.BLOCK_BORDER));
		configPanel.add(semiAutoSettingPanel);
		
		JPanel semiAutoSettingHeaderPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
		semiAutoSettingPanel.add(semiAutoSettingHeaderPanel, BorderLayout.NORTH);
		
		JLabel semiAutoSettingLabel = new JLabel(Captions.CHAIN_DEF_SEMIAUTO_SETTING);
		semiAutoSettingHeaderPanel.add(semiAutoSettingLabel);
		
		JPanel semiAutoSettingMainPanel = new VerticalFlowPanel();
		semiAutoSettingPanel.add(semiAutoSettingMainPanel, BorderLayout.CENTER);
		
		JButton semiAutoCookieSettingButton = new JButton(Captions.CHAIN_DEF_SEMIAUTO_SETTING_COOKIE);
		semiAutoCookieSettingButton.setToolTipText(Captions.CHAIN_DEF_SEMIAUTO_SETTING_COOKIE_TT);
		semiAutoCookieSettingButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				semiAutoAddCookieTransferSettings();
			}
		});
		semiAutoSettingMainPanel.add(semiAutoCookieSettingButton);
		
		JButton semiAutoTokenSettingButton = new JButton(Captions.CHAIN_DEF_SEMIAUTO_SETTING_TOKEN);
		semiAutoTokenSettingButton.setToolTipText(Captions.CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_TT);
		semiAutoTokenSettingButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				semiAutoAddTokenTransferSettings();
			}
		});
		semiAutoSettingMainPanel.add(semiAutoTokenSettingButton);
		
		configPanel.add(UiUtil.createSpacerM());
		
		JPanel configMainPanel = new JPanel();
		configPanel.add(configMainPanel);
		configMainPanel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel layoutControlPanel = new JPanel();
		FlowLayout flowLayout_4 = (FlowLayout) layoutControlPanel.getLayout();
		flowLayout_4.setVgap(0);
		configMainPanel.add(layoutControlPanel);
		
		JButton collapseButton = new JButton(Captions.CHAIN_DEF_SPLIT_COLLAPSE);
		collapseButton.setToolTipText(Captions.CHAIN_DEF_SPLIT_COLLAPSE_TT);
		collapseButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				collapseSettingPanels();
			}
		});
		layoutControlPanel.add(collapseButton);
		
		JButton expandButton = new JButton(Captions.CHAIN_DEF_SPLIT_EXPAND);
		expandButton.setToolTipText(Captions.CHAIN_DEF_SPLIT_EXPAND_TT);
		expandButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				getChainDefNodePanels().stream().forEach(ChainDefNodePanel::expandSettingPanel);
			}
		});
		layoutControlPanel.add(expandButton);
		
		layoutControlPanel.add(UiUtil.createSpacer());
		
		messageEditorsLayoutTypeSelectorPanel = new MessageEditorsLayoutTypeSelectorPanel(this::changeMessageEditorsLayout);
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
		autoScrollCheckBox.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				autoScrollWhenBreaking = autoScrollCheckBox.isSelected();
			}
		});
		scrollControlPanel.add(autoScrollCheckBox);
		
		nodesScrollPane = new JScrollPane();
		add(nodesScrollPane, BorderLayout.CENTER);
		
		nodesPanel = new JPanel();
		nodesScrollPane.setViewportView(nodesPanel);
		nodesPanel.setLayout(new BoxLayout(nodesPanel, BoxLayout.PAGE_AXIS));
		
		controlPanel = new JPanel();
		add(controlPanel, BorderLayout.SOUTH);
		controlPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel controlLeftPanel = new JPanel();
		controlPanel.add(controlLeftPanel, BorderLayout.WEST);
		
		JButton cancelButton = new JButton(Captions.CHAIN_DEF_CANCEL);
		controlLeftPanel.add(cancelButton);
		cancelButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				cancel();
			}
		});
		
		JPanel controlRightPanel = new JPanel();
		controlPanel.add(controlRightPanel, BorderLayout.EAST);
		
		saveMessageLabel = UiUtil.createTemporaryMessageArea();
		controlRightPanel.add(saveMessageLabel);
		
		saveButton = new JButton(Captions.CHAIN_DEF_SAVE);
		saveButton.setEnabled(clean);
		controlRightPanel.add(saveButton);
		saveButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				save();
			}
		});
		
		init(elementMessageDtos, clean);
	}

	private void init(List<MessageDto> elementMessageDtos, boolean clean) {
		nodesPanel.add(createAddButtonPanel());
		if(messageChainId == null || clean) {
			elementMessageDtos.forEach(elementMessageDto -> {
				var nodeDto = new MessageChainNodeDto();
				nodeDto.setMessageDto(elementMessageDto);
				if(messageDto != null) {
					nodeDto.setMain(elementMessageDto.getId().equals(messageDto.getId()));
				}
				addNodeTail(nodeDto);
			});
			return;
		}

		loadedMessageChainDto = Controller.getInstance().loadMessageChain(messageChainId);
		loadedMessageChainDto.getNodes().stream().forEach(nodeDto -> {
			addNodeTail(nodeDto);
		});
		messageChainPrcDate = loadedMessageChainDto.getPrcDate();

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

		getAddButtons().forEach(button -> button.setEnabled(!isRunningOrBreaking));
		getChainDefNodePanels().forEach(nodePanel -> nodePanel.setControlEnabled(!isRunningOrBreaking));
	}

	MessageChainDto getLoadedMessageChainDto() {
		return loadedMessageChainDto;
	}

	@SuppressWarnings("serial")
	private JPanel createAddButtonPanel() {
		var buttonPanel = new JPanel();
		((FlowLayout) buttonPanel.getLayout()).setAlignment(FlowLayout.LEFT);

		var addButton = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_ADD);
		addButton.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_ADD_TT);
		buttonPanel.add(addButton);
		addButton.addActionListener(new AbstractAction() {
			@Override public void actionPerformedSafe(ActionEvent e) {
				var nodePanel = addNode(buttonPanel);
				BurpApiUtil.i().customizeUiComponent(nodePanel);
				SwingUtilities.invokeLater(() -> {
					focusNode(nodePanel, false);
				});
				afterEdit();
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
		nodePanel.addEditListener(() -> afterEdit());
		nodesPanel.add(nodePanel, baseIndex + 1);
		nodesPanel.add(createAddButtonPanel(), baseIndex + 2);

		var nodeLabel = new ChainDefNodeLabelPanel(nodePanel);
		nodeLabel.addLabelMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				UiUtil.scrollSmoothFor(nodePanel, nodesScrollPane);
			}
		});
		nodeLabelsPanel.add(nodeLabel, getChainDefNodePanels().indexOf(nodePanel));

		UiUtil.repaint(this);
		return nodePanel;
	}

	void upNode(ChainDefNodePanel clickedNodePanel) {
		var index = indexOfNodePanel(clickedNodePanel);
		changeOrderOfNodes(index - 2, index);
	}
	void downNode(ChainDefNodePanel clickedNodePanel) {
		var index = indexOfNodePanel(clickedNodePanel);
		changeOrderOfNodes(index, index + 2);
	}
	private void changeOrderOfNodes(int index1, int index2) {
		if(index1 > index2) { //force index1 <= index2
			var tmp = index1;
			index1 = index2;
			index2 = tmp;
		}
		if(index1 < 0 || index2 >= nodesPanel.getComponentCount()) {
			return;
		}

		var nodePanel1 = nodesPanel.getComponent(index1);
		var nodePanel2 = nodesPanel.getComponent(index2);
		nodesPanel.remove(index2);
		nodesPanel.remove(index1);
		nodesPanel.add(nodePanel2, index1);
		nodesPanel.add(nodePanel1, index2);

		var nodeLabel1Index = getChainDefNodePanels().indexOf(nodesPanel.getComponent(index1));
		var nodeLabel1 = nodeLabelsPanel.getComponent(nodeLabel1Index);
		nodeLabelsPanel.remove(nodeLabel1Index);
		nodeLabelsPanel.add(nodeLabel1, nodeLabel1Index + 1);

		UiUtil.repaint(this);
	}

	void removeNode(JPanel clickedNodePanel) {
		var index = indexOfNodePanel(clickedNodePanel);
		nodesPanel.remove(index); // nodePanel
		nodesPanel.remove(index); // addButtonPanel
		UiUtil.repaint(this);
	}

	private int indexOfNodePanel(JPanel clickedNodePanel) {
		return Arrays.asList(nodesPanel.getComponents()).indexOf(clickedNodePanel);
	}

	private void semiAutoAddCookieTransferSettings() {
		var messageChainDto = makeChainDto();

		var cookies = messageChainDto.getNodes().stream()
				.filter(node -> node.getMessageDto().getResponseInfo() != null)
				.flatMap(node -> node.getMessageDto().getResponseInfo().getCookies().stream().map(cookie -> cookie.getName()))
				.distinct()
				.collect(Collectors.toList());

		if(cookies.isEmpty()) {
			UiUtil.showMessage(Captions.MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_COOKIE_EMPTY, this);
			return;
		}

		var selectedCookies = new MultipleSelectorPanel<String>(cookies).showDialog(Captions.MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_COOKIE, this);
		if(selectedCookies == null || selectedCookies.isEmpty()) {
			return;
		}

		var nodeDtos = messageChainDto.getNodes();
		var nodePanels = getChainDefNodePanels();

		IntStream.range(0, nodeDtos.size()).forEach(i -> {
			var nodeDto = nodeDtos.get(i);
			var nodePanel = nodePanels.get(i);

			//reqp
			nodeDto.getMessageDto().getRequestInfo().getParameters().stream()
					.filter(p -> p.getType() == RequestParameterType.COOKIE.getBurpId())
					.map(HttpRequestParameterDto::getName)
					.filter(selectedCookies::contains)
					.filter(cookie -> !nodeDto.getReqps().stream() //unique
										.filter(reqp -> reqp.getParamType() == RequestParameterType.COOKIE)
										.anyMatch(reqp -> cookie.equals(reqp.getParamName())))
					.filter(cookie -> IntStream.range(0, i) //check exist memorized var
										.anyMatch(j -> nodeDtos.get(j).getResps().stream()
														.anyMatch(resp -> cookie.equals(resp.getVarName()))))
					.forEach(cookie -> {
						var reqpDto = new MessageChainNodeReqpDto(RequestParameterType.COOKIE, cookie, SourceType.VAR, cookie);
						nodePanel.addReqp(reqpDto);
					});

			//resp
			var responseInfo = nodeDto.getMessageDto().getResponseInfo();
			if(responseInfo != null) {
				responseInfo.getCookies().stream()
					.map(HttpCookieDto::getName)
					.filter(selectedCookies::contains)
					.filter(cookie -> !nodeDto.getResps().stream() //unique
										.filter(resp -> resp.getParamType() == ResponseParameterType.COOKIE)
										.anyMatch(resp -> cookie.equals(resp.getParamName())))
					.forEach(cookie -> {
						var respDto = new MessageChainNodeRespDto(ResponseParameterType.COOKIE, cookie, cookie);
						nodePanel.addResp(respDto);
					});
			}
		});
	}

	private void semiAutoAddTokenTransferSettings() {
		var messageChainDto = makeChainDto();

		var tokenTransferSettings = new ChainDefTokenTransferSettingsPanel(messageChainDto).showDialog(this);
		if(tokenTransferSettings == null || tokenTransferSettings.isEmpty()) {
			return;
		}

		var nodeDtos = messageChainDto.getNodes();
		var nodePanels = getChainDefNodePanels();

		//resp
		for(int i = 0; i < nodeDtos.size(); i++) {
			var nodeDto = nodeDtos.get(i);
			var nodePanel = nodePanels.get(i);

			var docOptional = MessageUtil.parseResponseHtml(nodeDto.getMessageDto());
			if(docOptional.isEmpty()) {
				continue;
			}
			var doc = docOptional.get();

			tokenTransferSettings.stream()
				.filter(setting -> {
					var element = doc.selectFirst(setting.getSelector());
					return element != null && element.hasAttr(setting.getValueAttrName());
				})
				.filter(setting -> !nodeDto.getResps().stream() //unique
									.filter(resp -> resp.getParamType() == ResponseParameterType.HTML_TAG)
									.anyMatch(resp -> StringUtils.equals(resp.getParamName(), setting.getSettingString())))
				.forEach(setting -> nodePanel.addResp(new MessageChainNodeRespDto(ResponseParameterType.HTML_TAG, setting.getSettingString(), setting.getVarName())));
		}

		//reqp
		IntStream.range(0, nodeDtos.size()).forEach(i -> {
			var nodeDto = nodeDtos.get(i);
			var nodePanel = nodePanels.get(i);

			var requestParams = MessageUtil.extractRequestParams(nodeDto.getMessageDto());

			tokenTransferSettings.stream()
				.filter(setting -> setting.getRequestParam() != null && requestParams.contains(setting.getRequestParam()))
				.filter(setting -> !nodeDto.getReqps().stream() //unique
										.anyMatch(reqp -> reqp.getParamType() == setting.getRequestParam().getType() &&
															StringUtils.equals(reqp.getParamName(), setting.getRequestParam().getName())))
				.filter(setting -> IntStream.range(0, i) //check exist memorized var
										.anyMatch(j -> nodeDtos.get(j).getResps().stream()
														.anyMatch(resp -> StringUtils.equals(resp.getVarName(), setting.getVarName()))))
				.forEach(setting -> nodePanel.addReqp(new MessageChainNodeReqpDto(setting.getRequestParam().getType(), setting.getRequestParam().getName(), SourceType.VAR, setting.getVarName())));
		});
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
			UiUtil.scrollSmoothFor(chainDefNodePanel, nodesScrollPane);
		}
	}

	private void collapseSettingPanels() {
		getChainDefNodePanels().stream().forEach(ChainDefNodePanel::collapseSettingPanel);
	}

	private void changeMessageEditorsLayout(MessageEditorsLayoutType type) {
		getChainDefNodePanels().stream().forEach(nodePanel -> nodePanel.changeMessageEditorsLayout(type));
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

	private List<JButton> getAddButtons() {
		return Arrays.asList(nodesPanel.getComponents()).stream()
				.filter(component -> !(component instanceof ChainDefNodePanel))
				.map(buttonPanel -> (JButton)((JPanel)buttonPanel).getComponents()[0])
				.collect(Collectors.toList());
	}

	private MessageChainDto makeChainDto() {
		stopEditing();
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

	private void start(boolean isStep, boolean isForceAuthSessionRefresh) {
		var chainDto = makeChainDto();
		var error = ValidationUtil.validate(chainDto);
		if(error.isPresent()) {
			startMessageLabel.setText(error.get());
			return;
		}
		startMessageLabel.setText(null);

		startButton.setEnabled(false); //prevent double-click
		stepButton.setEnabled(false);

		if(breakingMessageChainRepeatDto != null) {
			resume(chainDto, isStep, isForceAuthSessionRefresh);
		} else {
			run(chainDto, isStep, isForceAuthSessionRefresh);
		}
		refreshControlsState();
	}

	private void run(MessageChainDto chainDto, boolean isStep, boolean isForceAuthSessionRefresh) {
		var chainDefNodePanels = getChainDefNodePanels();
		if(chainDefNodePanels.isEmpty()) {
			return;
		}
		Arrays.stream(nodeLabelsPanel.getComponents()).forEach(nodeLabel -> ((ChainDefNodeLabelPanel)nodeLabel).notifyStartChain());

		var times = getTimes();

		var authAccountDto = authAccountSelectorPanel.getSelectedAuthAccountDto();
		if(judgeIsAuthChain()) {
			runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
			return;
		}

		if(authAccountDto != null && (isForceAuthSessionRefresh || authAccountDto.isSessionIdsEmpty())) {
			Controller.getInstance().fetchNewAuthSession(authAccountDto, x -> {
				runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
			});
			return;
		}
		runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
	}

	private void resume(MessageChainDto chainDto, boolean isStep, boolean isForceAuthSessionRefresh) {
		var chainDefNodePanels = getChainDefNodePanels();
		var times = Integer.parseInt(timesCountdownLabel.getText());

		var authAccountDto = authAccountSelectorPanel.getSelectedAuthAccountDto();
		if(judgeIsAuthChain()) {
			runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
			return;
		}

		if(authAccountDto != null && isForceAuthSessionRefresh) {
			Controller.getInstance().fetchNewAuthSession(authAccountDto, x -> {
				runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
			});
			return;
		}
		runImpl(chainDefNodePanels, chainDto, authAccountDto, times, isStep);
	}

	private void runImpl(List<ChainDefNodePanel> chainDefNodePanels, MessageChainDto messageChainDto, AuthAccountDto authAccountDto, int times, boolean isStep) {
		SwingUtilities.invokeLater(() -> {
			timesCountdownLabel.setText(Integer.toString(times));
		});

		if(isStep) {
			OptionalInt nextNotSkipIndex;
			if(breakingMessageChainRepeatDto != null) {
				nextNotSkipIndex = getFirstNotSkipIndex(messageChainDto, breakingMessageChainRepeatDto.getCurrentIndex() + 1, messageChainDto.getNodes().size());
			} else {
				nextNotSkipIndex = getFirstNotSkipIndex(messageChainDto, 0, messageChainDto.getNodes().size());
			}

			if(nextNotSkipIndex.isPresent()) {
				messageChainDto.getNodes().get(nextNotSkipIndex.getAsInt()).setBreakpoint(true);
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
					chainDefNodePanel.setMessage(new HttpRequestResponseDto(breakingAppliedRequestForView, null, messageChainRepeatDto.getMessageChainDto().getNodes().get(index).getMessageDto().getMessage().getHttpService()), false);
					setIsCurrentNode(chainDefNodePanels, index);
					focusNode(chainDefNodePanel, true, true);
					refreshControlsState();
				});
				return;
			}

			if(!messageChainRepeatDto.getCurrentNodeDto().isSkip()) {
				SwingUtilities.invokeLater(() -> {
					chainDefNodePanels.get(index).setMessage(messageChainRepeatDto.getMessageRepeatDtos().get(index).getMessage(), true);
					setIsCurrentNode(chainDefNodePanels, null);
	
					if(messageChainRepeatDto.getMessageChainDto().getNodes().get(index).isMain() && needSaveHistory) {
						Controller.getInstance().refreshRepeatTablePanel(messageChainDto.getMainNode().get().getMessageDto().getId()); //TODO:improve...
					}
				});
			}

			var nextIndex = index + 1;
			if(nextIndex >= chainDefNodePanels.size()) { //case: last node
				breakingMessageChainRepeatDto = null;
				if(times - 1 > 0) {
					runImpl(chainDefNodePanels, messageChainDto, authAccountDto, times - 1, isStep); //recursive
				} else {
					SwingUtilities.invokeLater(() -> {
						breakingMessageChainRepeatDto = null;
						refreshControlsState();
						timesCountdownLabel.setText(Captions.CHAIN_DEF_RUN_DONE);

						if(judgeIsAuthChain() && authAccountDto != null) {
							Controller.getInstance().applyNewAuthSession(authAccountDto, messageChainRepeatDto);
						}

						if(autoStartMode) {
							UiUtil.getParentFrame(this).dispose();
						}
					});
				}
			}

		}, judgeIsAuthChain(), needSaveHistory, breakingMessageChainRepeatDto);
	}

	private OptionalInt getFirstNotSkipIndex(MessageChainDto messageChainDto, int startIndex, int endIndex) {
		return IntStream.range(startIndex, endIndex)
				.filter(i -> !messageChainDto.getNodes().get(i).isSkip())
				.findFirst();
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

	private void stopEditing() {
		presetVarsPanel.stopEditing();
		getChainDefNodePanels().forEach(ChainDefNodePanel::stopEditing);
	}

	private void save() {
		if(messageChainPrcDate != null && !messageChainPrcDate.equals(Controller.getInstance().getMessageChainPrcDate(messageChainId))) {
			if(!UiUtil.getConfirmAnswerDefaultCancel(Captions.MESSAGE_DUPLICATE_UPDATE, this)) {
				return;
			}
		}

		var messageChainDto = makeChainDto();
		var error = ValidationUtil.validate(messageChainDto);
		if(error.isPresent()) {
			saveMessageLabel.setText(error.get());
			return;
		}

		Controller.getInstance().saveMessageChain(messageChainDto, judgeIsAuthChain());
		messageChainId = messageChainDto.getId();
		messageChainPrcDate = messageChainDto.getPrcDate();

		UiUtil.showTemporaryMessage(saveMessageLabel, Captions.MESSAGE_SAVED);
		saveButton.setEnabled(false);
	}

	public void cancel() {
		if(!autoStartMode && saveButton.isEnabled() && !UiUtil.getConfirmAnswerDefaultCancel(Captions.MESSAGE_EXIT_WITHOUT_SAVE, saveButton)) {
			return;
		}

		authAccountSelectorPanel.unloaded();
		if(popupFrame != null) {
			UiUtil.closePopup(popupFrame);
		}
	}

	private void afterEdit() {
		saveButton.setEnabled(true);
	}


	public void setPopupFrame(JFrame popupFrame) {
		this.popupFrame = popupFrame;
	}

	public static void openChainFrame(MessageDto messageDto, Component triggerComponent) {
		var chainId = Controller.getInstance().getMessageChainIdByBaseMessageId(messageDto.getId());
		openChainFrame(messageDto, chainId, triggerComponent, messageDto.getName() + Captions.REPEATER_POPUP_TITLE_SUFFIX_CHAIN);
	}

	public static void openChainFrame(Integer chainId, Component triggerComponent, String title) {
		openChainFrame(null, chainId, triggerComponent, title);
	}

	private static void openChainFrame(MessageDto messageDto, Integer chainId, Component triggerComponent, String title) {
		var chainDefPanel = new ChainDefPanel(messageDto, chainId);
		chainDefPanel.setPopupFrame(UiUtil.popup(title, chainDefPanel, triggerComponent, we -> {chainDefPanel.cancel();}));
	}

	public static void openAutoStartChainModalFrame(Integer chainId, String title, AuthAccountDto authAccountDto) {
		var chainDefPanel = new ChainDefPanel(null, chainId);
		chainDefPanel.autoStartMode = true;

		chainDefPanel.authAccountSelectorPanel.setSelectedAuthAccount(authAccountDto, true);
		chainDefPanel.collapseSettingPanels();
		chainDefPanel.changeMessageEditorsLayout(MessageEditorsLayoutType.VERTICAL_SPLIT);
		chainDefPanel.controlPanel.setVisible(false);
		chainDefPanel.start(false, false);

		UiUtil.showModalFrame(title, chainDefPanel);
		chainDefPanel.cancel();
	}

}
