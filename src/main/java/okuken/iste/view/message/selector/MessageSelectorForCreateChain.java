package okuken.iste.view.message.selector;

import java.awt.Component;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JList;
import javax.swing.JOptionPane;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

public class MessageSelectorForCreateChain {

	@SuppressWarnings("serial")
	public static MessageDto showDialog(List<MessageDto> messages) {
		if(messages.isEmpty()) {
			return null;
		}

		var urlComboBox = new JComboBox<MessageDto>();
		urlComboBox.setMaximumRowCount(Sizes.MAX_ROW_COUNT_COMBOBOX);
		messages.forEach(message -> {
			urlComboBox.addItem(message);
		});

		var hasEditedChainIndexes = extractHasEditedChainIndexes(messages);
		urlComboBox.setRenderer(new DefaultListCellRenderer() {
			@Override
			public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
				var component =  super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
				if (hasEditedChainIndexes.contains(index)) {
					component.setForeground(Colors.COMBOBOX_FOREGROUND_GRAYOUT);
				}
				return component;
			}
		});

		var notHasEditedChainIndex = IntStream.range(0, messages.size()).filter(i -> !hasEditedChainIndexes.contains(i)).findFirst();
		if(notHasEditedChainIndex.isPresent()) {
			urlComboBox.setSelectedIndex(notHasEditedChainIndex.getAsInt());
		}

		if(UiUtil.showOptionDialog(
				BurpUtil.getBurpSuiteJFrame(),
				urlComboBox,
				Captions.MESSAGE_SELECT_CREATE_CHAIN_TARGET,
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null) == 0) {

			return urlComboBox.getItemAt(urlComboBox.getSelectedIndex());
		}
		return null;
	}

	private static List<Integer> extractHasEditedChainIndexes(List<MessageDto> messages) {
		return IntStream.range(0, messages.size())
				.filter(i -> {
					var messageChain = Controller.getInstance().getMessageChainByBaseMessageId(messages.get(i).getId());
					return messageChain != null && messageChain.isEditedByUser();
				})
				.mapToObj(Integer::valueOf)
				.collect(Collectors.toList());
	}

}
