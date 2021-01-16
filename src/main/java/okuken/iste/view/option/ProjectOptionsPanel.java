package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JTextField;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;

import javax.swing.JLabel;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Font;

public class ProjectOptionsPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField projectNameTextField;

	public ProjectOptionsPanel() {
		setLayout(null);
		
		JLabel projectNameLabel = new JLabel(Captions.PROJECT_OPTIONS_PROJECT_NAME + ":");
		projectNameLabel.setFont(new Font("MS UI Gothic", Font.PLAIN, 12));
		projectNameLabel.setBounds(30, 10, 100, 30);
		add(projectNameLabel);
		
		projectNameTextField = new JTextField();
		projectNameTextField.setBounds(140, 10, 210, 30);
		add(projectNameTextField);
		projectNameTextField.setColumns(20);
		refreshProjectName();
		
		JButton projectNameSaveButton = new JButton(Captions.PROJECT_OPTIONS_BUTTON_SAVE);
		projectNameSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//TODO: validation
				Controller.getInstance().updateProjectName(projectNameTextField.getText());
			}
		});
		projectNameSaveButton.setBounds(400, 10, 120, 30);
		add(projectNameSaveButton);

	}

	public void refreshProjectName() {
		projectNameTextField.setText(ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName());
	}

}
