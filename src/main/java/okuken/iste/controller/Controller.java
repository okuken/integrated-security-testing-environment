package okuken.iste.controller;

import java.io.File;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;

import burp.IHttpRequestResponse;
import burp.IParameter;
import okuken.iste.DatabaseManager;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageFilterDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.dto.PayloadDto;
import okuken.iste.logic.AuthLogic;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ExportLogic;
import okuken.iste.logic.MemoLogic;
import okuken.iste.logic.MessageLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.logic.RepeaterLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.SuitePanel;
import okuken.iste.view.SuiteTab;
import okuken.iste.view.auth.AuthPanel;
import okuken.iste.view.header.MainHeaderPanel;
import okuken.iste.view.memo.MessageMemoPanel;
import okuken.iste.view.memo.ProjectMemoPanel;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.table.MessageTableColumn;
import okuken.iste.view.message.table.MessageTableModel;
import okuken.iste.view.message.table.MessageTablePanel;
import okuken.iste.view.repeater.RepeaterPanel;

public class Controller {

	private static final Controller instance = new Controller();

	private SuiteTab suiteTab;
	private JTabbedPane mainTabbedPane;
	private JPanel mainPanel;
	private MainHeaderPanel mainHeaderPanel;

	private JFrame dockoutFrame;

	private MessageTablePanel messageTablePanel;
	private MessageTableModel messageTableModel;
	private JTable messageTable;

	private MessageEditorPanel orgMessageEditorPanel;
	private RepeaterPanel repeaterPanel;

	private MessageMemoPanel messageMemoPanel;

	private ProjectMemoPanel projectMemoPanel;

	private AuthPanel authPanel;

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
	public void setDockoutFrame(JFrame dockoutFrame) {
		this.dockoutFrame = dockoutFrame;
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
	public void setOrgMessageEditorPanel(MessageEditorPanel orgMessageEditorPanel) {
		this.orgMessageEditorPanel = orgMessageEditorPanel;
	}
	public void setRepeaterPanel(RepeaterPanel repeaterPanel) {
		this.repeaterPanel = repeaterPanel;
	}
	public void setMessageMemoPanel(MessageMemoPanel messageMemoPanel) {
		this.messageMemoPanel = messageMemoPanel;
	}
	public void setProjectMemoPanel(ProjectMemoPanel projectMemoPanel) {
		this.projectMemoPanel = projectMemoPanel;
	}
	public void setAuthPanel(AuthPanel authPanel) {
		this.authPanel = authPanel;
	}


	public void sendMessagesToSuiteTab(List<IHttpRequestResponse> messages) {
		BurpUtil.highlightTab(suiteTab);
		List<MessageDto> messageDtos = messages.stream()
				.map(message -> MessageLogic.getInstance().convertHttpRequestResponseToDto(message))
				.collect(Collectors.toList());
		MessageLogic.getInstance().saveMessages(messageDtos);
		this.messageTableModel.addRows(messageDtos);
		MessageLogic.getInstance().saveMessageOrder(this.messageTableModel.getRows()); // TODO: join transaction...
		messageDtos.forEach(messageDto -> MemoLogic.getInstance().saveMessageMemo(messageDto));

		refreshComponentsDependentOnMessages(this.messageTableModel.getRows());
	}

	private void refreshComponentsDependentOnMessages(List<MessageDto> messageDtos) {
		authPanel.refreshConfigPanel(messageDtos);
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

	/**
	 * @return top of selected messages
	 */
	public MessageDto getSelectedMessage() {
		return this.messageTablePanel.getSelectedMessage();
	}
	public List<MessageDto> getSelectedMessages() {
		return this.messageTablePanel.getSelectedMessages();
	}

	public String getSelectedMessagesForCopyToClipboad() {
		return this.messageTablePanel.getSelectedMessagesForCopyToClipboad();
	}

	public void refreshMessageDetailPanels(MessageDto dto) {
		this.orgMessageEditorPanel.setMessage(dto);
		this.repeaterPanel.setup(dto);
		this.messageMemoPanel.enablePanel(dto);
	}

	public void refreshMessageRepeaterPanel(int rowIndex) {
		repeaterPanel.setMessage(rowIndex);
	}

	public void refreshComponentsDependOnAuthAccounts() {
		repeaterPanel.refreshAuthAccountsComboBox();
	}

	public List<MessageRepeatDto> getRepeaterHistory(Integer orgMessageId) {
		return RepeaterLogic.getInstance().loadHistory(orgMessageId);
	}

	public MessageRepeatDto sendRepeaterRequest(byte[] request, AuthAccountDto authAccountDto, MessageDto orgMessageDto) {
		if(authAccountDto.getId() != null && authAccountDto.getSessionId() == null) {
			fetchNewAuthSession(authAccountDto);
		}

		//TODO:ÅöÅöimpl(load from db)ÅöÅö
		AuthConfigDto authConfigDto = new AuthConfigDto();
		authConfigDto.setSessionIdParamType(IParameter.PARAM_COOKIE);
		authConfigDto.setSessionIdParamName("SESSIONID");
		authConfigDto.setSelectedAuthAccountDto(authAccountDto);
		return RepeaterLogic.getInstance().sendRequest(request, authConfigDto, orgMessageDto, true);
	}

	public MessageRepeatDto sendAutoRequest(List<PayloadDto> payloadDtos, MessageDto orgMessageDto) {
		return RepeaterLogic.getInstance().sendRequest(payloadDtos, orgMessageDto, false);
	}

	public void saveMessageMemo(MessageDto messageDto) {
		if(messageDto.getMemoIdWithoutLoad() == null) {
			MemoLogic.getInstance().saveMessageMemo(messageDto);
			return;
		}
		MemoLogic.getInstance().updateMessageMemo(messageDto);
	}

	public String getProjectMemo() {
		return MemoLogic.getInstance().loadProjectMemo();
	}
	public void saveProjectMemo(String memo) {
		MemoLogic.getInstance().saveProjectMemo(memo);
	}

	public void exportMemoToTxtFile(File file) {
		ExportLogic.getInstance().exportMemoToTextFile(file, loadMessages(), getProjectMemo());
	}

	public List<AuthAccountDto> getAuthAccounts() {
		return AuthLogic.getInstance().loadAuthAccounts();
	}
	public void saveAuthAccount(AuthAccountDto authAccountDto) {
		AuthLogic.getInstance().saveAuthAccount(authAccountDto);
	}
	public void deleteAuthAccounts(List<AuthAccountDto> authAccountDtos) {
		AuthLogic.getInstance().deleteAuthAccounts(authAccountDtos);
	}

	public void fetchNewAuthSession(AuthAccountDto authAccountDto) {
		authPanel.sendLoginRequestAndSetSessionId(authAccountDto);
	}

	public void loadDatabase() {
		List<MessageDto> messageDtos = loadMessages();
		this.messageTableModel.addRows(messageDtos);
		applyMessageFilter();
		this.projectMemoPanel.refreshPanel();
		this.authPanel.refreshPanel(messageDtos);
		refreshComponentsDependOnAuthAccounts();
	}

	private List<MessageDto> loadMessages() {
		List<Integer> messageOrder = MessageLogic.getInstance().loadMessageOrder();
		List<MessageDto> messageDtos = MessageLogic.getInstance().loadMessages();

		return messageOrder.stream()
			.map(messageId -> messageDtos.stream().filter(dto -> dto.getId().equals(messageId)).findFirst().get())
			.collect(Collectors.toList());
	}

	public void applyMessageFilter() {
		mainHeaderPanel.applyMessageProgressFilter();
	}
	public void applyMessageFilter(MessageFilterDto messageFilterDto) {
		messageTablePanel.applyFilter(messageFilterDto);
	}

	public void changeDatabase(String dbFilePath) {
		ConfigLogic.getInstance().saveDbFilePath(dbFilePath);
		DatabaseManager.getInstance().changeDatabase(dbFilePath);
		ProjectLogic.getInstance().selectProject();
		mainHeaderPanel.refreshProjectName();
		reloadDatabase();
	}
	private void reloadDatabase() {
		this.messageTableModel.clearRows();
		this.messageTablePanel.setupTable(); // for fix bug: progress column control can't be active after to load empty messageTable.
		this.orgMessageEditorPanel.clearMessage();
		this.repeaterPanel.clear();
		this.messageMemoPanel.disablePanel();

		loadDatabase();
	}

	public void disposeDockoutFrame() {
		if(dockoutFrame != null) {
			dockoutFrame.dispose();
		}
	}

}