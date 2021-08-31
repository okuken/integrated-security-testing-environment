package okuken.iste.view;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.AbstractAction;
import javax.swing.KeyStroke;

import burp.IHttpRequestResponse;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.message.selector.MessageSelectorForSendToHistory;

public class KeyStrokeManager {

	private static final String ACTIONKEY_SEND_TO_ISTE = "SendToISTE";
	private static final String ACTIONKEY_SEND_TO_ISTE_HISTORY = "SendToISTEAsHistoryOfRepeat";

	static final KeyStroke KEYSTROKE_SEND_TO_ISTE = KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_SEND_TO_ISTE_HISTORY = KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK | ActionEvent.SHIFT_MASK, false);

	private static final KeyStrokeManager instance = new KeyStrokeManager();
	private KeyStrokeManager() {}
	public static KeyStrokeManager getInstance() {
		return instance;
	}

	@SuppressWarnings("serial")
	public void setupKeyStroke() {
		var proxyHistoryTable = BurpUtil.getBurpSuiteProxyHttpHistoryTable();

		proxyHistoryTable.getInputMap().put(KEYSTROKE_SEND_TO_ISTE, ACTIONKEY_SEND_TO_ISTE);
		proxyHistoryTable.getActionMap().put(ACTIONKEY_SEND_TO_ISTE, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				var selectedMessages = getSelectedBurpSuiteProxyHttpHistory();
				Controller.getInstance().sendMessagesToSuiteTab(selectedMessages);
			}
		});

		proxyHistoryTable.getInputMap().put(KEYSTROKE_SEND_TO_ISTE_HISTORY, ACTIONKEY_SEND_TO_ISTE_HISTORY);
		proxyHistoryTable.getActionMap().put(ACTIONKEY_SEND_TO_ISTE_HISTORY, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				var selectedMessages = getSelectedBurpSuiteProxyHttpHistory();
				var targetMessageDto = MessageSelectorForSendToHistory.showDialog(selectedMessages.toArray(new IHttpRequestResponse[0]));
				if(targetMessageDto == null) {
					return;
				}

				Controller.getInstance().sendMessagesToSuiteTabHistory(targetMessageDto, selectedMessages);
			}
		});

	}
	private List<IHttpRequestResponse> getSelectedBurpSuiteProxyHttpHistory() {
		var proxyHistoryTable = BurpUtil.getBurpSuiteProxyHttpHistoryTable();
		var proxyHistoryTableModel = proxyHistoryTable.getModel();
		var proxyHistory = BurpUtil.getCallbacks().getProxyHistory();

		return Arrays.stream(proxyHistoryTable.getSelectedRows())
				.mapToObj(proxyHistoryTable::convertRowIndexToModel)
				.map(tableModelRowIndex -> BurpUtil.convertToProxyHistoryIndex(proxyHistoryTableModel, tableModelRowIndex))
				.map(index -> proxyHistory[index])
				.filter(message -> message.getRequest() != null)
				.collect(Collectors.toList());
	}

	public void unloadKeyStroke() {
		var proxyHistoryTable = BurpUtil.getBurpSuiteProxyHttpHistoryTable();

		proxyHistoryTable.getInputMap().remove(KEYSTROKE_SEND_TO_ISTE);
		proxyHistoryTable.getActionMap().remove(ACTIONKEY_SEND_TO_ISTE);

		proxyHistoryTable.getInputMap().remove(KEYSTROKE_SEND_TO_ISTE_HISTORY);
		proxyHistoryTable.getActionMap().remove(ACTIONKEY_SEND_TO_ISTE_HISTORY);
	}

}
