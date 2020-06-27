package okuken.iste.controller;

import javax.swing.JTable;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;
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
		this.messageTableModel.addRows(messages);
		BurpUtil.highlightTab(suiteTab);
	}

	public boolean judgeIsMessageSelected() {
		return this.messageTable.getSelectedRow() >= 0;
	}
	public IHttpRequestResponse getSelectedMessage() {
		return this.messageTableModel.getRowMessage(this.messageTable.getSelectedRow());
	}

	public void refreshRequestDetailPanel() {
		IHttpRequestResponse message = getSelectedMessage();
		this.requestMessageEditor.setMessage(message.getRequest(), true);
		this.responseMessageEditor.setMessage(message.getResponse(), false);
	}

}