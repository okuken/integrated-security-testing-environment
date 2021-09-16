package okuken.iste.view.message.selector;

import java.awt.Component;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JOptionPane;

import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.logic.MessageLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

public class MessageSelectorForSendToHistory {

	@SuppressWarnings("serial")
	public static MessageDto showDialog(IHttpRequestResponse[] selectedMessages) {
		var messageDtos = Controller.getInstance().getMessages();
		if(messageDtos.isEmpty()) {
			return null;
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

		if(UiUtil.showOptionDialog(
				BurpUtil.getBurpSuiteJFrame(),
				urlComboBox,
				Captions.MESSAGE_SELECT_SEND_TO_HISTORY_TARGET,
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null) == 0) {

			return urlComboBox.getItemAt(urlComboBox.getSelectedIndex());
		}
		return null;
	}

	private static List<Integer> extractCandidateIndexes(List<MessageDto> messageDtos, IHttpRequestResponse[] selectedMessages) {
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
