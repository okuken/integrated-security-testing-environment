package okuken.iste.view.message.editor;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.function.Consumer;

import javax.swing.JComboBox;
import javax.swing.JPanel;

import okuken.iste.consts.Captions;

public class MessageEditorsLayoutTypeSelectorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JComboBox<MessageEditorsLayoutType> messageEditorsLayoutComboBox;

	public MessageEditorsLayoutTypeSelectorPanel(Consumer<MessageEditorsLayoutType> listener) {

		messageEditorsLayoutComboBox = new JComboBox<MessageEditorsLayoutType>();
		messageEditorsLayoutComboBox.setToolTipText(Captions.MESSAGE_EDITORS_LAYOUT_TYPE_COMBOBOX_TT);

		Arrays.stream(MessageEditorsLayoutType.values()).forEach(type -> {
			messageEditorsLayoutComboBox.addItem(type);
		});

		messageEditorsLayoutComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				listener.accept(getSelectedMessageEditorsLayoutType());
			}
		});

		add(messageEditorsLayoutComboBox);
	}

	public MessageEditorsLayoutType getSelectedMessageEditorsLayoutType() {
		return messageEditorsLayoutComboBox.getItemAt(messageEditorsLayoutComboBox.getSelectedIndex());
	}

}
