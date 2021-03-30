package okuken.iste.view;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComboBox;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;

public class ContextMenuFactory implements IContextMenuFactory {

	private ContextMenuFactory() {}
	public static ContextMenuFactory create() {
		return new ContextMenuFactory();
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
		if (selectedMessages == null) {
			return null;
		}

		return Arrays.asList(createSendToMenu(selectedMessages), createSendToHistoryMenu(selectedMessages));
	}

	private JMenuItem createSendToMenu(IHttpRequestResponse[] selectedMessages) {
		JMenuItem ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO, KeyEvent.VK_S);

		ret.addActionListener((ActionEvent e) -> {
			Controller.getInstance().sendMessagesToSuiteTab(Arrays.stream(selectedMessages)
					.filter(message -> message.getRequest() != null)
					.collect(Collectors.toList()));
		});

		return ret;
	}

	private JMenuItem createSendToHistoryMenu(IHttpRequestResponse[] selectedMessages) {
		var ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO_HISTORY);

		ret.addActionListener((ActionEvent e) -> {
			var messageDtos = Controller.getInstance().getMessages();
			if(messageDtos.isEmpty()) {
				return;
			}

			var urlComboBox = new JComboBox<MessageDto>();
			urlComboBox.setMaximumRowCount(Sizes.MAX_ROW_COUNT_COMBOBOX);
			messageDtos.forEach(messageDto -> {
				urlComboBox.addItem(messageDto);
			});

			if(JOptionPane.showOptionDialog(
					BurpUtil.getBurpSuiteJFrame(),
					urlComboBox,
					Captions.MESSAGE_SELECT_SEND_TO_HISTORY_TARGET,
					JOptionPane.OK_CANCEL_OPTION,
					JOptionPane.QUESTION_MESSAGE, null, null, null) == 0) {

				Controller.getInstance().sendMessagesToSuiteTabHistory(
						urlComboBox.getItemAt(urlComboBox.getSelectedIndex()),
						Arrays.stream(selectedMessages)
							.filter(message -> message.getRequest() != null)
							.collect(Collectors.toList()));
			}
		});

		return ret;
	}

}