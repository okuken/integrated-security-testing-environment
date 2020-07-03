package okuken.iste.controller;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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


	public void sendMessagesToSuiteTab(IHttpRequestResponse[] messages) {
		BurpUtil.highlightTab(suiteTab);
		List<MessageDto> messageDtos = Arrays.stream(messages)
				.map(message -> MessageLogic.getInstance().convertHttpRequestResponseToDto(message))
				.collect(Collectors.toList());
		MessageLogic.getInstance().saveMessages(messageDtos);
		this.messageTableModel.addRows(messageDtos);
	}

	public boolean judgeIsMessageSelected() {
		return this.messageTable.getSelectedRow() >= 0;
	}
	public MessageDto getSelectedMessage() {
		return this.messageTableModel.getRow(this.messageTable.getSelectedRow());
	}

	public void refreshRequestDetailPanel() {
		MessageDto dto = getSelectedMessage();
		if(dto.getMessage() == null) {
			MessageLogic.getInstance().loadMessageDetail(dto);
		}

		this.requestMessageEditor.setMessage(dto.getMessage().getRequest(), true);
		this.responseMessageEditor.setMessage(dto.getMessage().getResponse(), false);
	}

	public void loadDatabase() {
		this.messageTableModel.addRows(MessageLogic.getInstance().loadMessages());
	}

	public void reloadDatabase() {
		this.messageTableModel.clearRows();
		this.requestMessageEditor.setMessage(new byte[] {}, true);
		this.responseMessageEditor.setMessage(new byte[] {}, false);

		loadDatabase();
	}

//For test
	public void test1() {
		this.messageTableModel.addRows(MessageLogic.getInstance().loadMessages());
	}

}