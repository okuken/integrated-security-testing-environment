package okuken.iste.view;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.KeyStroke;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.message.selector.MessageSelectorForSendToHistory;

public class KeyStrokeManager {

	private static final String ACTIONKEY_SEND_TO_ISTE = "SendToISTE";
	private static final String ACTIONKEY_SEND_TO_ISTE_HISTORY = "SendToISTEAsHistoryOfRepeat";
	private static final String ACTIONKEY_CALC_DELETED_HISTORY = "calculateDeletedProxyHttpHistory";

	static final KeyStroke KEYSTROKE_SEND_TO_ISTE = KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_SEND_TO_ISTE_HISTORY = KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK | ActionEvent.SHIFT_MASK, false);
	static final KeyStroke KEYSTROKE_CALC_DELETED_HISTORY = KeyStroke.getKeyStroke(KeyEvent.VK_Q, ActionEvent.CTRL_MASK | ActionEvent.ALT_MASK, false);

	private static final KeyStrokeManager instance = new KeyStrokeManager();
	private KeyStrokeManager() {}
	public static KeyStrokeManager getInstance() {
		return instance;
	}

	private List<Integer> deletedProxyHttpHistoryNumbers;

	@SuppressWarnings("serial")
	public void setupKeyStroke() {
		var proxyHttpHistoryTable = BurpUtil.getBurpSuiteProxyHttpHistoryTable();
		if(proxyHttpHistoryTable == null) {
			BurpUtil.printStderr("setupKeyStroke failed.");
			return;
		}

		proxyHttpHistoryTable.getInputMap().put(KEYSTROKE_SEND_TO_ISTE, ACTIONKEY_SEND_TO_ISTE);
		proxyHttpHistoryTable.getActionMap().put(ACTIONKEY_SEND_TO_ISTE, new AbstractAction() {
			@Override
			public void actionPerformedSafe(ActionEvent e) {
				if(!judgeIsReadyToGetSelectedProxyHistoryIndexes()) {
					return;
				}

				var selectedIndexes = getSelectedProxyHistoryIndexes();
				UiUtil.invokeLater(() -> {
					Controller.getInstance().sendMessagesToSuiteTab(getProxyHistory(selectedIndexes));
				});
			}
		});

		proxyHttpHistoryTable.getInputMap().put(KEYSTROKE_SEND_TO_ISTE_HISTORY, ACTIONKEY_SEND_TO_ISTE_HISTORY);
		proxyHttpHistoryTable.getActionMap().put(ACTIONKEY_SEND_TO_ISTE_HISTORY, new AbstractAction() {
			@Override
			public void actionPerformedSafe(ActionEvent e) {
				if(!judgeIsReadyToGetSelectedProxyHistoryIndexes()) {
					return;
				}

				var selectedIndexes = getSelectedProxyHistoryIndexes();
				UiUtil.invokeLater(() -> {
					var selectedMessages = getProxyHistory(selectedIndexes);
					var targetMessageDto = MessageSelectorForSendToHistory.showDialog(selectedMessages.toArray(new IHttpRequestResponse[0]));
					if(targetMessageDto == null) {
						return;
					}
	
					Controller.getInstance().sendMessagesToSuiteTabHistory(targetMessageDto, selectedMessages);
				});
			}
		});

		proxyHttpHistoryTable.getInputMap().put(KEYSTROKE_CALC_DELETED_HISTORY, ACTIONKEY_CALC_DELETED_HISTORY);
		proxyHttpHistoryTable.getActionMap().put(ACTIONKEY_CALC_DELETED_HISTORY, new AbstractAction() {
			@Override
			public void actionPerformedSafe(ActionEvent e) {
				if(!judgeIsReadyToCalculateDeletedProxyHttpHistoryNumbers()) {
					return;
				}

				deletedProxyHttpHistoryNumbers = calculateDeletedProxyHttpHistoryNumbers();
				UiUtil.showInfoMessage(String.format(
							"Congratulations!\n"
							+ "It's ready to use Ctrl-Q and Ctrl+Shift-Q now!!\n"
							+ "\n"
							+ "...But, if you delete another history, you must do Ctrl+Alt-Q again.\n"
							+ "\n"
							+ "[Detected deleted history #: %s]",
							deletedProxyHttpHistoryNumbers.stream().map(i->i.toString()).collect(Collectors.joining(", "))),
							BurpUtil.getBurpSuiteProxyHttpHistoryTable());
			}
		});
	}

	private boolean judgeIsReadyToGetSelectedProxyHistoryIndexes() {
		if(deletedProxyHttpHistoryNumbers == null) {
			UiUtil.showMessage("If you want to use Ctrl-Q or Ctrl+Shift-Q, you need do Ctrl+Alt-Q first for calculate deleted history.", BurpUtil.getBurpSuiteProxyHttpHistoryTable());
			return false;
		}
		return true;
	}
	private List<Integer> getSelectedProxyHistoryIndexes() {
		var proxyHistoryTable = BurpUtil.getBurpSuiteProxyHttpHistoryTable();
		var proxyHistoryTableModel = proxyHistoryTable.getModel();
		return Arrays.stream(proxyHistoryTable.getSelectedRows())
				.mapToObj(proxyHistoryTable::convertRowIndexToModel)
				.map(tableModelRowIndex -> BurpUtil.extractProxyHttpHistoryNumber(proxyHistoryTableModel, tableModelRowIndex))
				.map(number -> number - (int)deletedProxyHttpHistoryNumbers.stream().filter(deletedNumber -> deletedNumber < number).count()) // consider deleted histories.
				.map(number -> number - 1) // because historyNumbers(#) start with 1, but historyIndexes start with 0. 
				.collect(Collectors.toList());
	}

	private List<IHttpRequestResponse> getProxyHistory(List<Integer> indexes) {
		var proxyHistory = BurpUtil.getCallbacks().getProxyHistory();
		return indexes.stream()
			.map(index -> proxyHistory[index])
			.filter(message -> message.getRequest() != null)
			.collect(Collectors.toList());
	}

	private boolean judgeIsReadyToCalculateDeletedProxyHttpHistoryNumbers() {
		if(!judgeIsShowAll()) {
			UiUtil.showMessage("To use Ctrl+Alt-Q, you need to set all filters off, so please open \"Filter settings\" and click \"Show all\" button.", BurpUtil.getBurpSuiteProxyHttpHistoryTable());
			return false;
		}
		return true;
	}
	private boolean judgeIsShowAll() {
		return BurpUtil.getBurpSuiteProxyHttpHistoryTable().getRowCount() == 
				BurpUtil.getCallbacks().getProxyHistory().length;
	}
	private List<Integer> calculateDeletedProxyHttpHistoryNumbers() {
		var proxyHistoryTableModel = BurpUtil.getBurpSuiteProxyHttpHistoryTable().getModel();
		var numbers = IntStream.range(0, proxyHistoryTableModel.getRowCount())
				.mapToObj(i -> BurpUtil.extractProxyHttpHistoryNumber(proxyHistoryTableModel, i))
				.collect(Collectors.toList());
		var maxNumber = numbers.stream().mapToInt(i->i).max().getAsInt();

		if(proxyHistoryTableModel.getRowCount() < maxNumber) { //case: some histories were deleted
			var ret = IntStream.range(1, maxNumber + 1).mapToObj(i->i).collect(Collectors.toList());
			numbers.forEach(ret::remove);
			return ret;
		}
		return Lists.newArrayList();
	}

	public void unloadKeyStroke() {
		if(!BurpUtil.isBurpSuiteProxyHttpHistoryTableExtracted()) {
			return;
		}
		var proxyHistoryTable = BurpUtil.getBurpSuiteProxyHttpHistoryTable();

		proxyHistoryTable.getInputMap().remove(KEYSTROKE_SEND_TO_ISTE);
		proxyHistoryTable.getActionMap().remove(ACTIONKEY_SEND_TO_ISTE);

		proxyHistoryTable.getInputMap().remove(KEYSTROKE_SEND_TO_ISTE_HISTORY);
		proxyHistoryTable.getActionMap().remove(ACTIONKEY_SEND_TO_ISTE_HISTORY);

		proxyHistoryTable.getInputMap().remove(KEYSTROKE_CALC_DELETED_HISTORY);
		proxyHistoryTable.getActionMap().remove(ACTIONKEY_CALC_DELETED_HISTORY);
	}

}
