package okuken.iste.controller;

import java.io.File;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import okuken.iste.dto.MessageDto;
import okuken.iste.logic.ExportLogic;
import okuken.iste.logic.MemoLogic;
import okuken.iste.logic.MessageLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.SuiteTab;
import okuken.iste.view.memo.MessageMemoPanel;
import okuken.iste.view.memo.ProjectMemoPanel;
import okuken.iste.view.message.table.MessageTableModel;

public class Controller {

	private static final Controller instance = new Controller();

	private SuiteTab suiteTab;
	private JTabbedPane mainTabbedPane;
	private JPanel mainPanel;

	private JFrame dockoutFrame;

	private MessageTableModel messageTableModel;
	private JTable messageTable;

	private IMessageEditor requestMessageEditor;
	private IMessageEditor responseMessageEditor;

	private MessageMemoPanel messageMemoPanel;

	private ProjectMemoPanel projectMemoPanel;

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
	public void setDockoutFrame(JFrame dockoutFrame) {
		this.dockoutFrame = dockoutFrame;
	}
	public void setMessageTableModel(MessageTableModel messageTableModel) {
		this.messageTableModel = messageTableModel;
	}
	public void setMessageTable(JTable messageTable) {
		this.messageTable = messageTable;
	}
	public void setRequestMessageEditor(IMessageEditor messageEditor) {
		this.requestMessageEditor = messageEditor;
	}
	public void setResponseMessageEditor(IMessageEditor messageEditor) {
		this.responseMessageEditor = messageEditor;
	}
	public void setMessageMemoPanel(MessageMemoPanel messageMemoPanel) {
		this.messageMemoPanel = messageMemoPanel;
	}
	public void setProjectMemoPanel(ProjectMemoPanel projectMemoPanel) {
		this.projectMemoPanel = projectMemoPanel;
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
	}

	public void initMessageTableColumnWidth() {
		//TODO: should reset column order...
		Enumeration<TableColumn> e = messageTable.getColumnModel().getColumns();
		for (int i = 0; e.hasMoreElements(); i++) {
			e.nextElement().setPreferredWidth(messageTableModel.getDefaultColumnWidth(i));
		}
	}

	public boolean judgeIsMessageSelected() {
		return this.messageTable.getSelectedRow() >= 0;
	}
	/**
	 * @return top of selected messages
	 */
	public MessageDto getSelectedMessage() {
		return this.messageTableModel.getRow(this.messageTable.getSelectedRow());
	}
	public List<MessageDto> getSelectedMessages() {
		int[] selectedRows = this.messageTable.getSelectedRows();
		return Arrays.stream(selectedRows).mapToObj(i -> messageTableModel.getRow(i)).collect(Collectors.toList());
	}

	public String getSelectedMessagesForCopyToClipboad() {
		return this.messageTableModel.getRowsAsTsv(this.messageTable.getSelectedRows());
	}

	public void refreshMessageDetailPanels(MessageDto dto) {
		this.requestMessageEditor.setMessage(dto.getMessage().getRequest(), true);
		this.responseMessageEditor.setMessage(
				dto.getMessage().getResponse() != null ? dto.getMessage().getResponse() : new byte[] {},
				false);

		this.messageMemoPanel.enablePanel(dto);
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

	public void loadDatabase() {
		this.messageTableModel.addRows(loadMessages());
		this.projectMemoPanel.refreshPanel();
	}

	private List<MessageDto> loadMessages() {
		List<Integer> messageOrder = MessageLogic.getInstance().loadMessageOrder();
		List<MessageDto> messageDtos = MessageLogic.getInstance().loadMessages();

		return messageOrder.stream()
			.map(messageId -> messageDtos.stream().filter(dto -> dto.getId().equals(messageId)).findFirst().get())
			.collect(Collectors.toList());
	}

	public void reloadDatabase() {
		this.messageTableModel.clearRows();
		this.requestMessageEditor.setMessage(new byte[] {}, true);
		this.responseMessageEditor.setMessage(new byte[] {}, false);
		this.messageMemoPanel.disablePanel();

		loadDatabase();
	}

	public void disposeDockoutFrame() {
		if(dockoutFrame != null) {
			dockoutFrame.dispose();
		}
	}

//For test
	public void test1() {
//		loadDatabase();
	}

}