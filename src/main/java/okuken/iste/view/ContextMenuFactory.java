package okuken.iste.view;

import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpApiUtil;
import okuken.iste.view.message.selector.MessageSelectorForSendToHistory;

public class ContextMenuFactory implements ContextMenuItemsProvider, IContextMenuFactory {

	private static final int AUTO_SEND_TO_ISTE_MASK = InputEvent.CTRL_DOWN_MASK;
	private static final int AUTO_SEND_TO_ISTE_HISTORY_MASK = InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK;

	private ContextMenuFactory() {}
	public static ContextMenuFactory create() {
		return new ContextMenuFactory();
	}

	@Override
	public List<JMenuItem> provideMenuItems(ContextMenuEvent event) {
		var selectedMessages = event.selectedRequestResponses();
		if(selectedMessages.isEmpty()) {
			return null;
		}
		return createMenuItemsImpl(selectedMessages.stream(), event.inputEvent().getModifiersEx(), event);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		var selectedMessages = invocation.getSelectedMessages();
		if (selectedMessages == null) {
			return null;
		}
		return createMenuItemsImpl(Arrays.stream(selectedMessages), invocation.getInputEvent().getModifiersEx(), invocation);
	}

	private List<JMenuItem> createMenuItemsImpl(Stream<?> selectedMessages, int modifiersEx, Object event) {
		var selectedMessageDtos = selectedMessages
				.map(selectedMessage -> BurpApiUtil.i().convertHttpRequestResponseToDto(selectedMessage))
				.collect(Collectors.toList());

		if(ConfigLogic.getInstance().getUserOptions().isUseKeyboardShortcutWithClick()) {
			if((modifiersEx & AUTO_SEND_TO_ISTE_HISTORY_MASK) == AUTO_SEND_TO_ISTE_HISTORY_MASK) {
				doActionIfNotDuplicate(event, selectedMessageDtos, this::sendToHistory);
				return null;
			}
			if((modifiersEx & AUTO_SEND_TO_ISTE_MASK) == AUTO_SEND_TO_ISTE_MASK) {
				doActionIfNotDuplicate(event, selectedMessageDtos, this::sendTo);
				return null;
			}
		}

		return Arrays.asList(createSendToMenu(selectedMessageDtos), createSendToHistoryMenu(selectedMessageDtos));
	}

	private Object currentInvocation;
	private void doActionIfNotDuplicate(Object invocation, List<HttpRequestResponseDto> selectedMessages, Consumer<List<HttpRequestResponseDto>> action) {
		if(invocation == currentInvocation) {
			return;
		}
		currentInvocation = invocation;
		action.accept(selectedMessages);
	}

	private JMenuItem createSendToMenu(List<HttpRequestResponseDto> selectedMessages) {
		JMenuItem ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO);
		ret.setAccelerator(KeyStrokeManager.KEYSTROKE_SEND_TO_ISTE);

		ret.addActionListener((ActionEvent e) -> {
			sendTo(selectedMessages);
		});

		return ret;
	}
	private void sendTo(List<HttpRequestResponseDto> selectedMessages) {
		Controller.getInstance().sendMessagesToSuiteTab(selectedMessages.stream()
				.filter(message -> message.getRequest() != null)
				.collect(Collectors.toList()));
	}

	private JMenuItem createSendToHistoryMenu(List<HttpRequestResponseDto> selectedMessages) {
		var ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO_HISTORY);
		ret.setAccelerator(KeyStrokeManager.KEYSTROKE_SEND_TO_ISTE_HISTORY);

		ret.addActionListener((ActionEvent e) -> {
			sendToHistory(selectedMessages);
		});

		return ret;
	}
	private void sendToHistory(List<HttpRequestResponseDto> selectedMessages) {
		var targetMessageDto = MessageSelectorForSendToHistory.showDialog(selectedMessages);
		if(targetMessageDto == null) {
			return;
		}

		Controller.getInstance().sendMessagesToSuiteTabHistory(
				targetMessageDto,
				selectedMessages.stream()
					.filter(message -> message.getRequest() != null)
					.collect(Collectors.toList()));
	}

}