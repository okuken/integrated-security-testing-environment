package okuken.iste.controller;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import okuken.iste.dto.MessageDto;
import okuken.iste.logic.MessageLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.SuiteTab;
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


	public void sendMessagesToSuiteTab(List<IHttpRequestResponse> messages) {
		BurpUtil.highlightTab(suiteTab);
		List<MessageDto> messageDtos = messages.stream()
				.map(message -> MessageLogic.getInstance().convertHttpRequestResponseToDto(message))
				.collect(Collectors.toList());
		MessageLogic.getInstance().saveMessages(messageDtos);
		this.messageTableModel.addRows(messageDtos);
		MessageLogic.getInstance().saveMessageOrder(this.messageTableModel.getRows()); // TODO: join transaction...
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

	public void refreshRequestDetailPanel(MessageDto dto) {
		this.requestMessageEditor.setMessage(dto.getMessage().getRequest(), true);
		this.responseMessageEditor.setMessage(
				dto.getMessage().getResponse() != null ? dto.getMessage().getResponse() : new byte[] {},
				false);
	}

	public void loadDatabase() {
		List<Integer> messageOrder = MessageLogic.getInstance().loadMessageOrder();
		List<MessageDto> messageDtos = MessageLogic.getInstance().loadMessages();

		this.messageTableModel.addRows(messageOrder.stream()
				.map(messageId -> messageDtos.stream().filter(dto -> dto.getId().equals(messageId)).findFirst().get())
				.collect(Collectors.toList()));
	}

	public void reloadDatabase() {
		this.messageTableModel.clearRows();
		this.requestMessageEditor.setMessage(new byte[] {}, true);
		this.responseMessageEditor.setMessage(new byte[] {}, false);

		loadDatabase();
	}

	public void disposeDockoutFrame() {
		if(dockoutFrame != null) {
			dockoutFrame.dispose();
		}
	}

//For test
	public void test1() {
		loadDatabase();
	}

}