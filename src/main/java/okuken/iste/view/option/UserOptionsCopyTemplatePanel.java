package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;

import okuken.iste.consts.Captions;
import okuken.iste.util.UiUtil;

import java.awt.FlowLayout;
import javax.swing.JTextArea;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class UserOptionsCopyTemplatePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTextField nameTextField;
	private JTextArea templateTextArea;

	public UserOptionsCopyTemplatePanel(UserOptionsCopyTemplatesPanel parentPanel, String name, String template) {
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
		
		templateTextArea = new JTextArea(template);
		templateTextArea.setToolTipText(Captions.USER_OPTIONS_COPY_TEMPLATE_TEMPLATE_TT);
		templateTextArea.setColumns(50);
		templateTextArea.setRows(10);
		UiUtil.addUndoRedoFeature(templateTextArea);
		
		JScrollPane templateScrollPane = new JScrollPane(templateTextArea);
		add(templateScrollPane);
		
	}

	String getTemplateName() {
		return nameTextField.getText();
	}

	String getTemplateBody() {
		return templateTextArea.getText();
	}

}
