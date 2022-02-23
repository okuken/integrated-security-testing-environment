package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JTextField;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.UiUtil;

import javax.swing.JLabel;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;

public class ProjectOptionsPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField projectNameTextField;
	private JLabel projectNameMessageLabel;

	public ProjectOptionsPanel() {
		
		JLabel projectNameLabel = new JLabel(Captions.PROJECT_OPTIONS_PROJECT_NAME + ":");
		
		projectNameTextField = new JTextField();
		projectNameTextField.setColumns(20);
		refreshProjectName();
		
		JButton projectNameSaveButton = new JButton(Captions.PROJECT_OPTIONS_BUTTON_SAVE);
		projectNameSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//TODO: validation
				Controller.getInstance().updateProjectName(projectNameTextField.getText());
				UiUtil.showTemporaryMessage(projectNameMessageLabel, Captions.MESSAGE_SAVED);
			}
		});
		
		projectNameMessageLabel = UiUtil.createTemporaryMessageArea();
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(projectNameLabel)
					.addGap(30)
					.addComponent(projectNameTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(projectNameSaveButton)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(projectNameMessageLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(projectNameLabel)
						.addComponent(projectNameTextField)
						.addComponent(projectNameSaveButton)
						.addComponent(projectNameMessageLabel)))
		);
		setLayout(groupLayout);

	}

	public void refreshProjectName() {
		projectNameTextField.setText(ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName());
	}

}
