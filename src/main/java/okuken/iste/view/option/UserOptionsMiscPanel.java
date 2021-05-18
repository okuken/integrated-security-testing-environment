package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JTextField;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;

import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Font;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;

public class UserOptionsMiscPanel extends JPanel {

	private static final String THEME_LIGHT = "Light";
	private static final String THEME_DARK = "Dark";

	private static final long serialVersionUID = 1L;
//	private JTextField userNameTextField; //TODO: impl
	private JTextField dbFileTextField;
	private JLabel dbFileMessageLabel;

	public UserOptionsMiscPanel() {
		setLayout(null);
		
//		JLabel userNameLabel = new JLabel(Captions.USER_OPTIONS_USER_NAME + ":");
//		userNameLabel.setFont(new Font("MS UI Gothic", Font.PLAIN, 12));
//		userNameLabel.setBounds(30, 60, 100, 30);
//		add(userNameLabel);
//		
//		userNameTextField = new JTextField();
//		userNameTextField.setBounds(140, 60, 210, 30);
//		add(userNameTextField);
//		userNameTextField.setColumns(20);
//		userNameTextField.setText(ConfigLogic.getInstance().getUserOptions().getUserName());
//		
//		JButton userNameSaveButton = new JButton("Save");
//		userNameSaveButton.addActionListener(new ActionListener() {
//			public void actionPerformed(ActionEvent e) {
//				//TODO: validation
//				ConfigLogic.getInstance().saveUserName(userNameTextField.getText());
//			}
//		});
//		userNameSaveButton.setBounds(400, 60, 120, 30);
//		add(userNameSaveButton);
		
		JLabel dbFileLabel = new JLabel(Captions.USER_OPTIONS_DB_FILE_PATH + ":");
		dbFileLabel.setFont(new Font("MS UI Gothic", Font.PLAIN, 12));
		dbFileLabel.setBounds(30, 25, 100, 30);
		add(dbFileLabel);
		
		dbFileTextField = new JTextField();
		dbFileTextField.setColumns(20);
		dbFileTextField.setBounds(110, 25, 300, 30);
		add(dbFileTextField);
		dbFileTextField.setText(ConfigLogic.getInstance().getUserOptions().getDbFilePath());
		
		JButton dbFileChooseButton = new JButton(Captions.FILECHOOSER);
		dbFileChooseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_DB_FILE, dbFileTextField.getText());
				if (fileChooser.showOpenDialog(UiUtil.getParentFrame(dbFileChooseButton)) == JFileChooser.APPROVE_OPTION) {
					dbFileTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
				}
			}
		});
		dbFileChooseButton.setBounds(410, 25, 20, 30);
		add(dbFileChooseButton);
		
		JButton dbFileSaveButton = new JButton(Captions.USER_OPTIONS_DB_FILE_BUTTON_SAVE);
		dbFileSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//TODO: validation
				Controller.getInstance().changeDatabase(dbFileTextField.getText());
				UiUtil.showTemporaryMessage(dbFileMessageLabel, Captions.MESSAGE_DONE);
			}
		});
		dbFileSaveButton.setBounds(440, 25, 120, 30);
		add(dbFileSaveButton);
		
		dbFileMessageLabel = UiUtil.createTemporaryMessageArea();
		dbFileMessageLabel.setBounds(570, 25, 200, 30);
		add(dbFileMessageLabel);
		
		JLabel themeLabel = new JLabel(Captions.USER_OPTIONS_THEME + ":");
		themeLabel.setBounds(30, 75, 45, 30);
		add(themeLabel);
		
		JComboBox<String> themeComboBox = new JComboBox<String>();
		themeComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ConfigLogic.getInstance().saveDarkTheme(themeComboBox.getSelectedItem().equals(THEME_DARK));
			}
		});
		themeComboBox.setModel(new DefaultComboBoxModel<String>(new String[] {THEME_LIGHT, THEME_DARK}));
		themeComboBox.setBounds(110, 75, 80, 30);
		if(ConfigLogic.getInstance().getUserOptions().isDarkTheme()) {
			themeComboBox.setSelectedItem(THEME_DARK);
		}
		add(themeComboBox);
		
		JLabel themeExplanationLabel = new JLabel(Captions.USER_OPTIONS_THEME_EXPLANATION);
		themeExplanationLabel.setBounds(200, 75, 700, 30);
		add(themeExplanationLabel);

	}
}
