package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.util.UiUtil;

import java.awt.FlowLayout;
import javax.swing.JTextArea;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.stream.IntStream;
import java.awt.event.ActionEvent;
import javax.swing.JComboBox;
import java.awt.GridLayout;

public class UserOptionsCopyTemplatePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTextField nameTextField;
	private JComboBox<String> mnemonicComboBox;
	private JTextArea templateTextArea;
	private JButton upButton;
	private JButton downButton;

	public UserOptionsCopyTemplatePanel(UserOptionsCopyTemplatesPanel parentPanel, String name, String template, String mnemonic) {
		var that = this;
		FlowLayout flowLayout = (FlowLayout) getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		
		JButton deleteButton = new JButton(Captions.DELETE);
		deleteButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				parentPanel.removeTemplatePanel(that);
			}
		});
		add(deleteButton);
		
		nameTextField = new JTextField(name);
		nameTextField.setToolTipText(Captions.USER_OPTIONS_COPY_TEMPLATE_NAME_TT);
		nameTextField.setColumns(15);
		UiUtil.addUndoRedoFeature(nameTextField);
		add(nameTextField);
		
		mnemonicComboBox = new JComboBox<String>();
		mnemonicComboBox.setToolTipText(Captions.USER_OPTIONS_COPY_TEMPLATE_MNEMONIC_TT);
		mnemonicComboBox.addItem(" ");
		IntStream.range(KeyEvent.VK_0, KeyEvent.VK_9 + 1).forEach(k -> {mnemonicComboBox.addItem(Character.toString(k));});
		IntStream.range(KeyEvent.VK_A, KeyEvent.VK_Z + 1).forEach(k -> {mnemonicComboBox.addItem(Character.toString(k));});
		if(mnemonic != null) {
			mnemonicComboBox.setSelectedItem(mnemonic);
		}
		add(mnemonicComboBox);
		
		templateTextArea = new JTextArea(template);
		templateTextArea.setToolTipText(Captions.USER_OPTIONS_COPY_TEMPLATE_TEMPLATE_TT);
		templateTextArea.setColumns(50);
		templateTextArea.setRows(10);
		UiUtil.addUndoRedoFeature(templateTextArea);
		
		JScrollPane templateScrollPane = new JScrollPane(templateTextArea);
		add(templateScrollPane);
		
		JPanel sortPanel = new JPanel();
		add(sortPanel);
		sortPanel.setLayout(new GridLayout(2, 1, 0, 0));
		
		upButton = new JButton(Captions.UP);
		upButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				parentPanel.upTemplatePanel(that);
			}
		});
		sortPanel.add(upButton);
		
		downButton = new JButton(Captions.DOWN);
		downButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				parentPanel.downTemplatePanel(that);
			}
		});
		sortPanel.add(downButton);
		
	}

	String getTemplateName() {
		return nameTextField.getText();
	}

	String getTemplateMnemonic() {
		var ret = mnemonicComboBox.getItemAt(mnemonicComboBox.getSelectedIndex());
		if(StringUtils.isBlank(ret)) {
			return null;
		}
		return ret;
	}

	String getTemplateBody() {
		return templateTextArea.getText();
	}

	void focus() {
		UiUtil.focus(templateTextArea);
	}

}
