package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.UIManager;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.KeyStrokeManager;

import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.awt.event.ActionEvent;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;

import org.apache.commons.lang3.StringUtils;

public class UserOptionsMiscPanel extends JPanel {

	private static final String THEME_LIGHT = "Light";
	private static final String THEME_DARK = "Dark";

	private static final long serialVersionUID = 1L;

	private JTextField dbFileTextField;
	private JLabel dbFileMessageLabel;

	private JComboBox<String> themeComboBox;

	private JCheckBox useKeyboardShortcutQCheckBox;
	private JCheckBox useKeyboardShortcutWithClickCheckBox;

	public UserOptionsMiscPanel() {
		
		JLabel dbFileLabel = new JLabel(Captions.USER_OPTIONS_DB_FILE_PATH + ":");
		
		dbFileTextField = new JTextField();
		dbFileTextField.setColumns(30);
		
		JButton dbFileChooseButton = new JButton(Captions.FILECHOOSER);
		dbFileChooseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_DB_FILE, dbFileTextField.getText());
				if (fileChooser.showOpenDialog(UiUtil.getParentFrame(dbFileChooseButton)) == JFileChooser.APPROVE_OPTION) {
					dbFileTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
				}
			}
		});
		
		JButton dbFileSaveButton = new JButton(Captions.USER_OPTIONS_DB_FILE_BUTTON_SAVE);
		dbFileSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//TODO: validation
				Controller.getInstance().changeDatabase(dbFileTextField.getText());
				UiUtil.showTemporaryMessage(dbFileMessageLabel, Captions.MESSAGE_DONE);
			}
		});
		
		dbFileMessageLabel = UiUtil.createTemporaryMessageArea();
		
		JLabel themeLabel = new JLabel(Captions.USER_OPTIONS_THEME + ":");
		
		themeComboBox = new JComboBox<String>();
		themeComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ConfigLogic.getInstance().saveDarkTheme(themeComboBox.getSelectedItem().equals(THEME_DARK));
			}
		});
		themeComboBox.setModel(new DefaultComboBoxModel<String>(new String[] {THEME_LIGHT, THEME_DARK}));
		UIManager.addPropertyChangeListener(new PropertyChangeListener() {
			@Override
			public void propertyChange(PropertyChangeEvent evt) {
				if(!StringUtils.equals(evt.getPropertyName(), "lookAndFeel")) {
					return;
				}

				var isDarkTheme = BurpUtil.isDarkTheme();
				if(isDarkTheme.isPresent()) {
					themeComboBox.setSelectedItem(isDarkTheme.get() ? THEME_DARK : THEME_LIGHT);
				}
			}
		});
		
		JLabel themeExplanationLabel = new JLabel(Captions.USER_OPTIONS_THEME_EXPLANATION);
		
		JLabel useKeyboardShortcutLabel = new JLabel(Captions.USER_OPTIONS_USE_KEYBOARD_SHORTCUT + ":");
		
		useKeyboardShortcutQCheckBox = new JCheckBox(Captions.USER_OPTIONS_USE_KEYBOARD_SHORTCUT_Q);
		useKeyboardShortcutQCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var useKeyboardShortcutQ = useKeyboardShortcutQCheckBox.isSelected();

				ConfigLogic.getInstance().saveUseKeyboardShortcutQ(useKeyboardShortcutQ);
				applyUseKeyboardShortcutQ(useKeyboardShortcutQ);
			}
		});
		
		useKeyboardShortcutWithClickCheckBox = new JCheckBox(Captions.USER_OPTIONS_USE_KEYBOARD_SHORTCUT_WITH_CLICK);
		useKeyboardShortcutWithClickCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ConfigLogic.getInstance().saveUseKeyboardShortcutWithClick(useKeyboardShortcutWithClickCheckBox.isSelected());
			}
		});

		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(useKeyboardShortcutLabel)
						.addComponent(dbFileLabel)
						.addComponent(themeLabel))
					.addGap(30)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(dbFileTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addComponent(dbFileChooseButton)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(dbFileSaveButton)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(dbFileMessageLabel))
						.addComponent(useKeyboardShortcutQCheckBox)
						.addComponent(useKeyboardShortcutWithClickCheckBox)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(themeComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(themeExplanationLabel)))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(dbFileLabel)
						.addComponent(dbFileTextField)
						.addComponent(dbFileChooseButton)
						.addComponent(dbFileSaveButton)
						.addComponent(dbFileMessageLabel))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(themeLabel)
						.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
							.addComponent(themeComboBox)
							.addComponent(themeExplanationLabel)))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addGroup(groupLayout.createSequentialGroup()
						.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
							.addComponent(useKeyboardShortcutLabel)
							.addComponent(useKeyboardShortcutQCheckBox))
						.addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(useKeyboardShortcutWithClickCheckBox)))
		);
		setLayout(groupLayout);

		Controller.getInstance().setUserOptionsMiscPanel(this);
		refresh(true);
	}

	public void refresh() {
		refresh(false);
	}
	private void refresh(boolean isInit) {
		dbFileTextField.setText(ConfigLogic.getInstance().getUserOptions().getDbFilePath());

		themeComboBox.setSelectedItem(ConfigLogic.getInstance().getUserOptions().isDarkTheme() ? THEME_DARK : THEME_LIGHT);

		useKeyboardShortcutQCheckBox.setSelected(ConfigLogic.getInstance().getUserOptions().isUseKeyboardShortcutQ());
		if(!isInit) { // if init, registerExtenderCallbacks method will do it.
			applyUseKeyboardShortcutQ(ConfigLogic.getInstance().getUserOptions().isUseKeyboardShortcutQ());
		}

		useKeyboardShortcutWithClickCheckBox.setSelected(ConfigLogic.getInstance().getUserOptions().isUseKeyboardShortcutWithClick());
	}

	private void applyUseKeyboardShortcutQ(boolean useKeyboardShortcutQ) {
		if(!useKeyboardShortcutQ) {
			KeyStrokeManager.getInstance().unloadKeyStroke();
			return;
		}

		KeyStrokeManager.getInstance().setupKeyStroke();
	}

}
