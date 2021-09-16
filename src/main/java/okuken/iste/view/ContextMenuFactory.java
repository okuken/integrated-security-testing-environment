package okuken.iste.view;

import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.view.message.selector.MessageSelectorForSendToHistory;

public class ContextMenuFactory implements IContextMenuFactory {

	private static final int AUTO_SEND_TO_ISTE_MASK = InputEvent.CTRL_DOWN_MASK;
	private static final int AUTO_SEND_TO_ISTE_HISTORY_MASK = InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK;

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

		var modifiersEx = invocation.getInputEvent().getModifiersEx();
		if((modifiersEx & AUTO_SEND_TO_ISTE_HISTORY_MASK) == AUTO_SEND_TO_ISTE_HISTORY_MASK) {
			doActionIfNotDuplicate(invocation, selectedMessages, this::sendToHistory);
			return null;
		}
		if((modifiersEx & AUTO_SEND_TO_ISTE_MASK) == AUTO_SEND_TO_ISTE_MASK) {
			doActionIfNotDuplicate(invocation, selectedMessages, this::sendTo);
			return null;
		}

		return Arrays.asList(createSendToMenu(selectedMessages), createSendToHistoryMenu(selectedMessages));
	}

	private IContextMenuInvocation currentInvocation;
	private void doActionIfNotDuplicate(IContextMenuInvocation invocation, IHttpRequestResponse[] selectedMessages, Consumer<IHttpRequestResponse[]> action) {
		if(invocation == currentInvocation) {
			return;
		}
		currentInvocation = invocation;
		action.accept(selectedMessages);
	}

	private JMenuItem createSendToMenu(IHttpRequestResponse[] selectedMessages) {
		JMenuItem ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO);
		ret.setAccelerator(KeyStrokeManager.KEYSTROKE_SEND_TO_ISTE);

		ret.addActionListener((ActionEvent e) -> {
			sendTo(selectedMessages);
		});

		return ret;
	}
	private void sendTo(IHttpRequestResponse[] selectedMessages) {
		Controller.getInstance().sendMessagesToSuiteTab(Arrays.stream(selectedMessages)
				.filter(message -> message.getRequest() != null)
				.collect(Collectors.toList()));
	}

	private JMenuItem createSendToHistoryMenu(IHttpRequestResponse[] selectedMessages) {
		var ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO_HISTORY);
		ret.setAccelerator(KeyStrokeManager.KEYSTROKE_SEND_TO_ISTE_HISTORY);

		ret.addActionListener((ActionEvent e) -> {
			sendToHistory(selectedMessages);
		});

		return ret;
	}
	private void sendToHistory(IHttpRequestResponse[] selectedMessages) {
		var targetMessageDto = MessageSelectorForSendToHistory.showDialog(selectedMessages);
		if(targetMessageDto == null) {
			return;
		}

		Controller.getInstance().sendMessagesToSuiteTabHistory(
				targetMessageDto,
				Arrays.stream(selectedMessages)
					.filter(message -> message.getRequest() != null)
					.collect(Collectors.toList()));
	}

}