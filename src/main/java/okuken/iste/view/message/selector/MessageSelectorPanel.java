package okuken.iste.view.message.selector;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;

import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.view.message.editor.MessageEditorPanel;

public class MessageSelectorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JComboBox<MessageDto> urlComboBox;
	private MessageEditorPanel messageEditorPanel;

	private boolean refreshingFlag = false;

	public MessageSelectorPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel urlPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) urlPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(urlPanel, BorderLayout.NORTH);
		
		urlComboBox = new JComboBox<MessageDto>();
		urlComboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if(!refreshingFlag && e.getStateChange() == ItemEvent.SELECTED) {
					refreshMessageEditorPanel();
				}
			}
		});
		urlPanel.add(urlComboBox);
		
		messageEditorPanel = new MessageEditorPanel(null, true, false, true);
		add(messageEditorPanel, BorderLayout.CENTER);
		
		Controller.getInstance().addMessageSelectPanel(this);
		
		SwingUtilities.invokeLater(() -> {
			refreshPanel(Controller.getInstance().getMessages());
		});
	}

	public void refreshPanel(List<MessageDto> messageDtos) {
		var refreshingFlagBk = refreshingFlag;
		refreshingFlag = true;
		try {
			var selectedMessageId = urlComboBox.getItemCount() > 0 ? urlComboBox.getItemAt(urlComboBox.getSelectedIndex()).getId() : null; 

			urlComboBox.removeAllItems();
			urlComboBox.setMaximumRowCount(Sizes.MAX_ROW_COUNT_COMBOBOX);
			messageDtos.forEach(messageDto -> {
				urlComboBox.addItem(messageDto);
			});

			if(selectedMessageId != null) {
				var selectedMessageDtoOptional = messageDtos.stream().filter(messageDto -> messageDto.getId().equals(selectedMessageId)).findFirst();
				if(selectedMessageDtoOptional.isPresent()) {
					urlComboBox.setSelectedItem(selectedMessageDtoOptional.get());
				}
			}

			refreshMessageEditorPanel();

		} finally {
			refreshingFlag = refreshingFlagBk;
		}
	}

	private void refreshMessageEditorPanel() {
		if(urlComboBox.getItemCount() <= 0) {
			messageEditorPanel.clearMessage();
			return;
		}
		messageEditorPanel.setMessage(urlComboBox.getItemAt(urlComboBox.getSelectedIndex()));
	}

	public MessageEditorPanel getMessageEditorPanel() {
		return messageEditorPanel;
	}
}
