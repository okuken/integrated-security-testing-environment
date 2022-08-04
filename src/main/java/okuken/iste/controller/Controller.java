package okuken.iste.controller;

import java.io.File;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;
import okuken.iste.DatabaseManager;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.AuthApplyConfigDto;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainRepeatDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageFilterDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.dto.MessageRepeatRedirectDto;
import okuken.iste.dto.ProjectMemoDto;
import okuken.iste.enums.OrderType;
import okuken.iste.logic.AuthLogic;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ExportLogic;
import okuken.iste.logic.MemoLogic;
import okuken.iste.logic.MessageChainLogic;
import okuken.iste.logic.MessageFilterLogic;
import okuken.iste.logic.MessageLogic;
import okuken.iste.logic.OrderLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.logic.RepeaterLogic;
import okuken.iste.plugin.PluginInfo;
import okuken.iste.plugin.PluginManager;
import okuken.iste.plugin.api.IIsteContextMenuFactory;
import okuken.iste.plugin.api.IIstePluginTab;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.SuitePanel;
import okuken.iste.view.SuiteTab;
import okuken.iste.view.auth.AuthPanel;
import okuken.iste.view.header.MainHeaderPanel;
import okuken.iste.view.memo.MessageMemoPanel;
import okuken.iste.view.memo.ProjectMemoPanel;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.selector.MessageSelectorPanel;
import okuken.iste.view.message.table.MessageTableColumn;
import okuken.iste.view.message.table.MessageTableModel;
import okuken.iste.view.message.table.MessageTablePanel;
import okuken.iste.view.message.table.MessageTablePopupMenu;
import okuken.iste.view.option.ProjectOptionsPanel;
import okuken.iste.view.option.UserOptionsCopyTemplatesPanel;
import okuken.iste.view.option.UserOptionsMiscPanel;
import okuken.iste.view.option.UserOptionsTemplatePanel;
import okuken.iste.view.plugin.PluginsPanel;
import okuken.iste.view.repeater.RepeatMasterPanel;
import okuken.iste.view.repeater.RepeatTablePopupMenu;
import okuken.iste.view.repeater.RepeaterPanel;

public class Controller {

	private static final Controller instance = new Controller();

	private SuiteTab suiteTab;
	private JTabbedPane mainTabbedPane;
	private JPanel mainPanel;
	private MainHeaderPanel mainHeaderPanel;

	private MessageTablePanel messageTablePanel;
	private MessageTableModel messageTableModel;
	private JTable messageTable;

	private JTabbedPane messageDetailTabbedPane;
	private MessageEditorPanel orgMessageEditorPanel;
	private RepeatMasterPanel repeatMasterPanel;
	private RepeaterPanel repeaterPanel;
	private RepeatTablePopupMenu repeatTablePopupMenu;
//	private ChainRepeaterPanel chainRepeaterPanel;

	private MessageMemoPanel messageMemoPanel;

	private ProjectMemoPanel projectMemoPanel;

	private AuthPanel authPanel;

	private JTabbedPane toolsTabbedPane;

	private List<MessageSelectorPanel> messageSelectPanels = Lists.newArrayList();

	private ProjectOptionsPanel projectOptionsPanel;

	private UserOptionsTemplatePanel userOptionsTemplatePanel;

	private UserOptionsCopyTemplatesPanel userOptionsCopyTemplatesPanel;

	private UserOptionsMiscPanel userOptionsMiscPanel;

	private PluginsPanel pluginsPanel;

	private Controller() {}
	public static Controller getInstance() {
		return instance;
	}
	
	public void setSuiteTab(SuiteTab suiteTab) {
		this.suiteTab = suiteTab;
	}
	public void setMainTabbedPane(JTabbedPane mainTabbedPane) {
		this.mainTabbedPane = mainTabbedPane;
	}
	public JTabbedPane getMainTabbedPane() {
		return mainTabbedPane;
	}
	public void setMainPanel(JPanel mainPanel) {
		this.mainPanel = mainPanel;
	}
	public JPanel getMainPanel() {
		return this.mainPanel;
	}
	public void setMainHeaderPanel(MainHeaderPanel mainHeaderPanel) {
		this.mainHeaderPanel = mainHeaderPanel;
	}
	public void setMessageTablePanel(MessageTablePanel messageTablePanel) {
		this.messageTablePanel = messageTablePanel;
	}
	public void setMessageTableModel(MessageTableModel messageTableModel) {
		this.messageTableModel = messageTableModel;
	}
	public void setMessageTable(JTable messageTable) {
		this.messageTable = messageTable;
	}
	public void setMessageDetailTabbedPane(JTabbedPane messageDetailTabbedPane) {
		this.messageDetailTabbedPane = messageDetailTabbedPane;
	}
	public JTabbedPane getMessageDetailTabbedPane() {
		return messageDetailTabbedPane;
	}
	public void setOrgMessageEditorPanel(MessageEditorPanel orgMessageEditorPanel) {
		this.orgMessageEditorPanel = orgMessageEditorPanel;
	}
	public void setRepeatMasterPanel(RepeatMasterPanel repeatMasterPanel) {
		this.repeatMasterPanel = repeatMasterPanel;
	}
	public void setRepeaterPanel(RepeaterPanel repeaterPanel) {
		this.repeaterPanel = repeaterPanel;
	}
	public void setRepeatTablePopupMenu(RepeatTablePopupMenu repeatTablePopupMenu) {
		this.repeatTablePopupMenu = repeatTablePopupMenu;
	}
//	public void setChainRepeaterPanel(ChainRepeaterPanel chainRepeaterPanel) {
//		this.chainRepeaterPanel = chainRepeaterPanel;
//	}
	public void setMessageMemoPanel(MessageMemoPanel messageMemoPanel) {
		this.messageMemoPanel = messageMemoPanel;
	}
	public void setProjectMemoPanel(ProjectMemoPanel projectMemoPanel) {
		this.projectMemoPanel = projectMemoPanel;
	}
	public void addMessageSelectPanel(MessageSelectorPanel messageSelectPanel) {
		messageSelectPanels.add(messageSelectPanel);
	}
	public void setAuthPanel(AuthPanel authPanel) {
		this.authPanel = authPanel;
	}
	public void setToolsTabbedPane(JTabbedPane toolsTabbedPane) {
		this.toolsTabbedPane = toolsTabbedPane;
	}
	public JTabbedPane getToolsTabbedPane() {
		return toolsTabbedPane;
	}
	public void setProjectOptionsPanel(ProjectOptionsPanel projectOptionsPanel) {
		this.projectOptionsPanel = projectOptionsPanel;
	}
	public void setUserOptionsTemplatePanel(UserOptionsTemplatePanel userOptionsTemplatePanel) {
		this.userOptionsTemplatePanel = userOptionsTemplatePanel;
	}
	public void setUserOptionsCopyTemplatesPanel(UserOptionsCopyTemplatesPanel userOptionsCopyTemplatesPanel) {
		this.userOptionsCopyTemplatesPanel = userOptionsCopyTemplatesPanel;
	}
	public void setUserOptionsMiscPanel(UserOptionsMiscPanel userOptionsMiscPanel) {
		this.userOptionsMiscPanel = userOptionsMiscPanel;
	}
	public void setPluginsPanel(PluginsPanel pluginsPanel) {
		this.pluginsPanel = pluginsPanel;
	}


	public void sendMessagesToSuiteTab(List<IHttpRequestResponse> messages) {
		BurpUtil.highlightTab(suiteTab);
		addMessages(messages.stream()
				.map(message -> MessageLogic.getInstance().convertHttpRequestResponseToDto(message))
				.collect(Collectors.toList()));
	}
	public void addMessages(List<MessageDto> messageDtos) {
		MessageLogic.getInstance().saveMessages(messageDtos);
		this.messageTableModel.addRows(messageDtos);
		MessageLogic.getInstance().saveMessageOrder(this.messageTableModel.getRows()); // TODO: join transaction...
		messageDtos.forEach(messageDto -> MemoLogic.getInstance().saveMessageMemo(messageDto));

		applyMessageFilter();
		refreshComponentsDependentOnMessages(this.messageTableModel.getRows());
	}

	public void sendMessagesToSuiteTabHistory(MessageDto targetMessageDto, List<IHttpRequestResponse> messages) {
		BurpUtil.highlightTab(suiteTab);
		RepeaterLogic.getInstance().saveAsRepeatHistory(targetMessageDto, messages);
		refreshRepeatTablePanel(targetMessageDto);
	}

	public String deleteMessages() {
		var selectedRowIndexs = getSelectedRowIndexs();

		var err = selectedRowIndexs.stream()
				.map(messageTableModel::getRow)
				.map(message -> {
					var parentChainNames = MessageChainLogic.getInstance().getMessageChainOwnerNamesByNodeMessageWhithoutItself(message);
					if(parentChainNames.isEmpty()) {
						return "";
					}
					return new StringBuilder()
							.append("\"")
							.append(message.toString())
							.append("\" is included by chain:")
							.append(System.lineSeparator())
							.append(parentChainNames.stream().map(n -> " - " + n).collect(Collectors.joining(System.lineSeparator())))
							.toString();
				})
				.collect(Collectors.joining(System.lineSeparator()));

		if(!StringUtils.isBlank(err)) {
			return new StringBuilder()
					.append("Failed to delete.")
					.append(System.lineSeparator())
					.append(err)
					.toString();
		}

		Collections.reverse(selectedRowIndexs);

		for(var rowIndex: selectedRowIndexs) {
			var dto = messageTableModel.removeRow(rowIndex);
			MessageLogic.getInstance().deleteMessage(dto);
		}
		MessageLogic.getInstance().saveMessageOrder(this.messageTableModel.getRows()); // TODO: join transaction...

		applyMessageFilter();
		refreshComponentsDependentOnMessages(this.messageTableModel.getRows());
		return null;
	}

	private void refreshComponentsDependentOnMessages(List<MessageDto> messageDtos) {
//		authPanel.refreshConfigPanel(messageDtos);
		messageSelectPanels.forEach(panel -> panel.refreshPanel(messageDtos));
	}

	public void initSizeRatioOfParts() {
		initMessageTableColumnWidth();
		((SuitePanel)suiteTab.getUiComponent()).initDividerLocation();
	}
	private void initMessageTableColumnWidth() {
		Enumeration<TableColumn> e = messageTable.getColumnModel().getColumns();
		for (int i = 0; e.hasMoreElements(); i++) {
			e.nextElement().setPreferredWidth(MessageTableColumn.getByCaption(messageTable.getColumnName(i)).getWidth());
		}
	}

	public List<MessageDto> getMessages() {
		return this.messageTablePanel.getMessages();
	}

	public List<Integer> getSelectedRowIndexs() {
		return this.messageTablePanel.getSelectedRowIndexs();
	}

	public List<MessageDto> getSelectedMessages() {
		return this.messageTablePanel.getSelectedMessages();
	}

	public String getSelectedMessagesForCopyToClipboad() {
		return this.messageTablePanel.getSelectedMessagesForCopyToClipboad();
	}

	public MessageTableColumn getSelectedMessageColumnType() {
		return messageTablePanel.getSelectedColumnType();
	}

	public void updateMessage(MessageDto dto) {
		updateMessage(dto, true);
	}
	public void updateMessage(MessageDto dto, boolean applyMessageFilter) {
		MessageLogic.getInstance().updateMessage(dto);

		var index = getMessages().indexOf(dto);
		messageTableModel.fireTableRowsUpdated(index, index);
		if(applyMessageFilter) {
			applyMessageFilter();
		}
	}

	public void refreshMessageTablePopupMenu() {
		((MessageTablePopupMenu)messageTable.getComponentPopupMenu()).refresh();
	}

	public void refreshMessageDetailPanels(MessageDto dto) {
		this.orgMessageEditorPanel.setMessage(dto);
		this.repeatMasterPanel.setup(dto);
		this.repeaterPanel.setup(dto);
//		this.chainRepeaterPanel.setup(dto);
		this.messageMemoPanel.enablePanel(dto);
	}

	public void refreshMessageRepeaterPanel(int rowIndex) {
		repeaterPanel.setMessage(rowIndex);
	}

	public void refreshRepeatTablePanel(Integer messageId) {
		refreshRepeatTablePanel(getMessages().stream().filter(messageDto -> messageId.equals(messageDto.getId())).findFirst().get());
	}
	public void refreshRepeatTablePanel(MessageDto messageDto) {
		//TODO: improve...
		messageDto.setRepeatList(null);
		if(repeaterPanel.getOrgMessageDto() != null && repeaterPanel.getOrgMessageDto().getId().equals(messageDto.getId())) {
			repeaterPanel.refresh();
		}
	}

	public void refreshUserOptionsPanel() {
		userOptionsTemplatePanel.refresh();
		userOptionsCopyTemplatesPanel.refresh();
		userOptionsMiscPanel.refresh();
	}

	public List<MessageRepeatDto> getSelectedMessageRepeats() {
		return repeaterPanel.getSelectedMessageRepeatDtos();
	}
	public MessageDto getSelectedMessageRepeatOrg() {
		return repeaterPanel.getOrgMessageDto();
	}

	public MessageChainRepeatDto sendMessageChain(MessageChainDto messageChainDto, AuthAccountDto authAccountDto, BiConsumer<MessageChainRepeatDto, Integer> callback, boolean forAuth, boolean needSaveHistory, MessageChainRepeatDto breakingMessageChainRepeatDto) {
		return MessageChainLogic.getInstance().sendMessageChain(messageChainDto, authAccountDto, callback, forAuth, needSaveHistory, breakingMessageChainRepeatDto);
	}

	public MessageRepeatDto sendRepeaterRequest(byte[] request, AuthAccountDto authAccountDto, MessageDto orgMessageDto, Consumer<MessageRepeatDto> callback) {
		return sendRepeaterRequest(request, authAccountDto, orgMessageDto, callback, true);
	}
	public MessageRepeatDto sendRepeaterRequest(byte[] request, AuthAccountDto authAccountDto, MessageDto orgMessageDto, Consumer<MessageRepeatDto> callback, boolean needSaveHistory) {
		return RepeaterLogic.getInstance().sendRequest(request, authAccountDto, orgMessageDto, callback, false, needSaveHistory);
	}

	public void sendRepeaterRequest(boolean forceAuthSessionRefresh) {
		repeaterPanel.sendRequest(forceAuthSessionRefresh);
	}

	public MessageRepeatRedirectDto sendFollowRedirectRequest(byte[] request, byte[] response, MessageDto orgMessageDto, Consumer<MessageRepeatRedirectDto> callback) {
		return RepeaterLogic.getInstance().sendFollowRedirectRequest(request, response, orgMessageDto, callback);
	}

	public void saveRepeatMaster(MessageDto messageDto) {
		MessageLogic.getInstance().saveRepeatMaster(messageDto);
		repeatMasterPanel.refreshPanel();
	}

	public void saveMessageMemo(MessageDto messageDto) {
		if(messageDto.getMemoIdWithoutLoad() == null) {
			MemoLogic.getInstance().saveMessageMemo(messageDto);
			return;
		}
		MemoLogic.getInstance().updateMessageMemo(messageDto);
	}

	public List<ProjectMemoDto> getProjectMemos() {
		var ret = MemoLogic.getInstance().loadProjectMemos();
		if(!ret.isEmpty()) {
			return ret;
		}

		var templates = ConfigLogic.getInstance().getUserOptions().getProjectMemoTemplates();
		if(templates == null) {
			return ret;
		}

		return templates.stream()
			.map(template -> {
				var dto = new ProjectMemoDto();
				dto.setMemo(template);
				MemoLogic.getInstance().saveProjectMemo(dto); // [CAUTION] insert template values
				return dto;
			})
			.collect(Collectors.toList());

	}
	public void saveProjectMemo(ProjectMemoDto dto) {
		MemoLogic.getInstance().saveProjectMemo(dto);
	}

	public void exportMemoToTxtFile(File file, boolean useFilter) {
		var messages = loadMessages();
		if(useFilter) {
			messages = MessageFilterLogic.getInstance().filter(messages, mainHeaderPanel.getMessageFilterDto());
		}

		ExportLogic.getInstance().exportMemoToTextFile(file, messages, getProjectMemos());
	}

	public List<AuthAccountDto> getAuthAccounts() {
		return ConfigLogic.getInstance().getAuthAccountDtos();
	}
	public void saveNewAuthAccount(AuthAccountDto newAuthAccountDto, boolean keepOldSessionId, List<AuthAccountDto> allAuthAccountDtos) {
		AuthLogic.getInstance().saveAuthAccount(newAuthAccountDto, keepOldSessionId);
		saveAuthAccountsOrderImpl(allAuthAccountDtos);
		ConfigLogic.getInstance().reloadAuthAccountDtos();
	}
	public void saveAuthAccount(AuthAccountDto authAccountDto, boolean keepOldSessionId) {
		AuthLogic.getInstance().saveAuthAccount(authAccountDto, keepOldSessionId);
		ConfigLogic.getInstance().reloadAuthAccountDtos();
	}
	public void deleteAuthAccounts(List<AuthAccountDto> deleteAuthAccountDtos, List<AuthAccountDto> restAuthAccountDtos) {
		AuthLogic.getInstance().deleteAuthAccounts(deleteAuthAccountDtos);
		saveAuthAccountsOrderImpl(restAuthAccountDtos);
		ConfigLogic.getInstance().reloadAuthAccountDtos();
	}
	public void saveAuthAccountsOrder(List<AuthAccountDto> authAccountDtos) {
		saveAuthAccountsOrderImpl(authAccountDtos);
		ConfigLogic.getInstance().reloadAuthAccountDtos();
	}
	private void saveAuthAccountsOrderImpl(List<AuthAccountDto> authAccountDtos) {
		OrderLogic.getInstance().saveOrder(authAccountDtos, OrderType.AUTH_ACCOUNT);
	}

	public void fetchNewAuthSession(AuthAccountDto authAccountDto, Consumer<AuthAccountDto> callback) {
		AuthLogic.getInstance().sendLoginRequestAndSetSessionId(authAccountDto, x -> {
			ConfigLogic.getInstance().setAuthAccountSessionIds(x);
			if(callback != null) {
				callback.accept(x);
			}
		});
	}

	private void clearAuthAccountsSession() {
		AuthLogic.getInstance().clearAuthAccountsSession();
		ConfigLogic.getInstance().reloadAuthAccountDtos();
	}

	public void saveNewAuthApplyConfig(AuthApplyConfigDto authApplyConfigDto, boolean keepOldSessionId, List<AuthApplyConfigDto> allAuthApplyConfigDtos) {
		AuthLogic.getInstance().saveAuthApplyConfig(authApplyConfigDto);
		saveAuthApplyConfigsOrderImpl(allAuthApplyConfigDtos);
		if(!keepOldSessionId) {
			clearAuthAccountsSession();
		}
	}
	public void saveAuthApplyConfig(AuthApplyConfigDto authApplyConfigDto, boolean keepOldSessionId) {
		AuthLogic.getInstance().saveAuthApplyConfig(authApplyConfigDto);
		if(!keepOldSessionId) {
			clearAuthAccountsSession();
		}
	}
	public void deleteAuthApplyConfigs(List<AuthApplyConfigDto> authApplyConfigDtos, boolean keepOldSessionId, List<AuthApplyConfigDto> restAuthApplyConfigDtos) {
		AuthLogic.getInstance().deleteAuthApplyConfigs(authApplyConfigDtos);
		saveAuthApplyConfigsOrderImpl(restAuthApplyConfigDtos);
		if(!keepOldSessionId) {
			clearAuthAccountsSession();
		}
	}
	public void saveAuthApplyConfigsOrder(List<AuthApplyConfigDto> authApplyConfigDtos) {
		saveAuthApplyConfigsOrderImpl(authApplyConfigDtos);
	}
	private void saveAuthApplyConfigsOrderImpl(List<AuthApplyConfigDto> authApplyConfigDtos) {
		OrderLogic.getInstance().saveOrder(authApplyConfigDtos, OrderType.AUTH_APPLY_CONFIG);
	}

	public MessageChainDto getMessageChainByBaseMessageId(Integer messageId) {
		var chainId = getMessageChainIdByBaseMessageId(messageId);
		if(chainId == null) {
			return null;
		}
		return loadMessageChain(chainId);
	}

	public Integer getMessageChainIdByBaseMessageId(Integer messageId) {
		return MessageChainLogic.getInstance().getMessageChainIdByBaseMessageId(messageId);
	}

	public MessageChainDto loadMessageChain(Integer messageChainId) {
		return MessageChainLogic.getInstance().loadMessageChain(messageChainId);
	}

	public void saveMessageChain(MessageChainDto messageChainDto, boolean isAuthChain) {
		MessageChainLogic.getInstance().saveMessageChain(messageChainDto, isAuthChain);

		if(isAuthChain) {
			ConfigLogic.getInstance().getAuthConfig().setAuthMessageChainDto(messageChainDto);
			clearAuthAccountsSession();
		} else {
			messageTableModel.refreshRow(messageChainDto.getMessageId());
		}
	}

	public PluginInfo loadPlugin(String pluginJarFilePath) {
		return PluginManager.getInstance().load(pluginJarFilePath);
	}
	public PluginInfo loadPluginFromClasspath() {
		return PluginManager.getInstance().loadFromClasspath();
	}
	public void unloadPlugin(PluginInfo pluginInfo) {
		PluginManager.getInstance().unload(pluginInfo);
	}

	public void addIsteContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		((MessageTablePopupMenu)messageTable.getComponentPopupMenu()).getPluginPopupMenuListener().addIsteContextMenuFactories(isteContextMenuFactories);
	}
	public void removeIsteContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		((MessageTablePopupMenu)messageTable.getComponentPopupMenu()).getPluginPopupMenuListener().removeIsteContextMenuFactories(isteContextMenuFactories);
	}

	public void addIsteRepeaterContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		repeatTablePopupMenu.getPluginPopupMenuListener().addIsteContextMenuFactories(isteContextMenuFactories);
	}
	public void removeIsteRepeaterContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		repeatTablePopupMenu.getPluginPopupMenuListener().removeIsteContextMenuFactories(isteContextMenuFactories);
	}

	public void addPluginTabs(List<IIstePluginTab> pluginTabs) {
		pluginsPanel.addPluginTabs(pluginTabs);
	}
	public void removePluginTabs(List<IIstePluginTab> pluginTabs) {
		pluginsPanel.removePluginTabs(pluginTabs);
	}


	public void loadDatabase() {
		List<MessageDto> messageDtos = loadMessages();
		this.messageTableModel.addRows(messageDtos);
		applyMessageFilter();
		this.projectMemoPanel.refreshPanel();
		this.authPanel.refreshPanel(messageDtos);
		refreshComponentsDependentOnMessages(messageDtos);
	}

	private List<MessageDto> loadMessages() {
		List<Integer> messageOrder = MessageLogic.getInstance().loadMessageOrder();
		List<MessageDto> messageDtos = MessageLogic.getInstance().loadMessages();

		return messageOrder.stream()
			.map(messageId -> messageDtos.stream().filter(dto -> dto.getId().equals(messageId)).findFirst().get())
			.collect(Collectors.toList());
	}

	public void applyMessageFilter() {
		mainHeaderPanel.applyMessageFilter();
	}
	/**
	 * @return number of rows after filtering
	 */
	public int applyMessageFilter(MessageFilterDto messageFilterDto) {
		return messageTablePanel.applyFilter(messageFilterDto);
	}

	public void updateProjectName(String projectName) {
		ProjectLogic.getInstance().updateProjectName(projectName);
		refreshComponentsDependOnProjectName();
	}

	private void refreshComponentsDependOnProjectName() {
		mainHeaderPanel.refreshProjectName();
		projectOptionsPanel.refreshProjectName();
	}

	public void changeDatabase(String dbFilePath) {
		changeDatabaseOnly(dbFilePath);
		changeProject(true);
	}
	public void changeDatabaseOnly(String dbFilePath) {
		ConfigLogic.getInstance().saveDbFilePath(dbFilePath);
		DatabaseManager.getInstance().changeDatabase(dbFilePath);
		if(userOptionsMiscPanel != null) {
			userOptionsMiscPanel.refresh();
		}
	}
	public void changeProject(boolean autoSelect) {
		ProjectLogic.getInstance().selectProject(autoSelect);
		refreshComponentsDependOnProjectName();
		ConfigLogic.getInstance().resetProjectOptionsDto();
		reloadDatabase();

		PluginManager.getInstance().invokeProjectChanged();
	}
	private void reloadDatabase() {
		this.messageTableModel.clearRows();
		this.messageTablePanel.setupTable(); // for fix bug: progress column control can't be active after to load empty messageTable.
		this.orgMessageEditorPanel.clearMessage();
		this.repeatMasterPanel.clear();
		this.repeaterPanel.clear();
		this.messageMemoPanel.disablePanel();
		UiUtil.disposePopupFrames();

		loadDatabase();
	}


	public void loadPlugins() {
		pluginsPanel.loadUserOption();
	}

}