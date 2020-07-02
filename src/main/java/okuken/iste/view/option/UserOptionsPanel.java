package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JTextField;

import okuken.iste.DatabaseManager;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;

import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Font;

public class UserOptionsPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField userNameTextField;
	private JTextField dbFileTextField;

	public UserOptionsPanel() {
		setLayout(null);
		
		JLabel userNameLabel = new JLabel(Captions.USER_OPTIONS_USER_NAME + ":");
		userNameLabel.setFont(new Font("MS UI Gothic", Font.PLAIN, 12));
		userNameLabel.setBounds(30, 10, 100, 30);
		add(userNameLabel);
		
		userNameTextField = new JTextField();
		userNameTextField.setBounds(140, 10, 210, 30);
		add(userNameTextField);
		userNameTextField.setColumns(20);
		userNameTextField.setText(ConfigLogic.getInstance().getUserOptions().getUserName());
		
		JButton userNameSaveButton = new JButton("Save");
		userNameSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//TODO: validation
				ConfigLogic.getInstance().saveUserName(userNameTextField.getText());
			}
		});
		userNameSaveButton.setBounds(400, 10, 120, 30);
		add(userNameSaveButton);
		
		JLabel dbFileLabel = new JLabel(Captions.USER_OPTIONS_DB_FILE_PATH + ":");
		dbFileLabel.setFont(new Font("MS UI Gothic", Font.PLAIN, 12));
		dbFileLabel.setBounds(30, 60, 100, 30);
		add(dbFileLabel);
		
		dbFileTextField = new JTextField();
		dbFileTextField.setColumns(20);
		dbFileTextField.setBounds(140, 60, 210, 30);
		add(dbFileTextField);
		dbFileTextField.setText(ConfigLogic.getInstance().getUserOptions().getDbFilePath());
		
		JButton dbFileChooseButton = new JButton("...");
		dbFileChooseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_DB_FILE);
				if (fileChooser.showOpenDialog(BurpUtil.getBurpSuiteJFrame()) == JFileChooser.APPROVE_OPTION) {
					dbFileTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
				}
			}
		});
		dbFileChooseButton.setBounds(350, 60, 20, 30);
		add(dbFileChooseButton);
		
		JButton dbFileSaveButton = new JButton("Save & Reload");
		dbFileSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//TODO: validation
				String dbFilePath = dbFileTextField.getText();
				ConfigLogic.getInstance().saveDbFilePath(dbFilePath);
				DatabaseManager.getInstance().changeDatabase(dbFilePath);
				Controller.getInstance().reloadDatabase();
			}
		});
		dbFileSaveButton.setBounds(400, 60, 120, 30);
		add(dbFileSaveButton);

	}
}
