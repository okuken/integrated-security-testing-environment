package okuken.iste.view;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.logic.MessageLogic;
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

	@SuppressWarnings("serial")
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

			var candidateIndexes = extractCandidateIndexes(messageDtos, selectedMessages);
			urlComboBox.setRenderer(new DefaultListCellRenderer() {
				@Override
				public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
					var component =  super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
					if (candidateIndexes.contains(index)) {
						component.setForeground(Colors.COMBOBOX_FOREGROUND_HIGHLIGHT);
					}
					return component;
				}
			});
			if(!candidateIndexes.isEmpty()) {
				urlComboBox.setSelectedIndex(candidateIndexes.get(0));
			}

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

	private List<Integer> extractCandidateIndexes(List<MessageDto> messageDtos, IHttpRequestResponse[] selectedMessages) {
		var selectedMessageDtos = Arrays.asList(selectedMessages).stream()
				.map(message -> MessageLogic.getInstance().convertHttpRequestResponseToDto(message))
				.collect(Collectors.toList());

		return IntStream.range(0, messageDtos.size())
				.filter(i -> selectedMessageDtos.stream().anyMatch(selected -> {
					var messageDto = messageDtos.get(i);
					return selected.getUrlShortest().equals(messageDto.getUrlShortest()) &&
							selected.getMethod().equals(messageDto.getMethod());}))
				.mapToObj(Integer::valueOf)
				.collect(Collectors.toList());
	}

}