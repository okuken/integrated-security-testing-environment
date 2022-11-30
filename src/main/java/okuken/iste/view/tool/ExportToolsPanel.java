package okuken.iste.view.tool;

import javax.swing.JPanel;

import okuken.iste.client.BurpApiClient;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.io.File;
import java.awt.event.ActionEvent;
import javax.swing.JCheckBox;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JLabel;

public class ExportToolsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final File USER_OPTIONS_FILE_DEFAULT = new File(System.getProperty("user.home"), "iste_user_options.json");

	private JCheckBox filterCheckBox;

	private JButton exportUserOptionsButton;
	private JButton importUserOptionsButton;
	private JButton clearUserOptionsButton;
	private JLabel userOptionsMessageLabel;

	public ExportToolsPanel() {
		
		JLabel notesLabel = new JLabel(Captions.TOOLS_EXPORT_LABEL_MEMO + ":");
		
		JButton exportMemoToTxtFileButton = new JButton(Captions.TOOLS_EXPORT_BUTTON_EXPORT_MEMO_TO_TXT_FILE);
		exportMemoToTxtFileButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String defaultFileName = String.format("%s_%s.md", ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName(), UiUtil.nowForFilename());
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_EXPORT_FILE, defaultFileName);
				switch (fileChooser.showSaveDialog(UiUtil.getParentFrame(exportMemoToTxtFileButton))) {
					case JFileChooser.APPROVE_OPTION:
						Controller.getInstance().exportMemoToTxtFile(fileChooser.getSelectedFile(), filterCheckBox.isSelected());
						break;
					default:
						break;
				};
			}
		});
		
		filterCheckBox = new JCheckBox(Captions.TOOLS_EXPORT_CHECKBOX_FILTER);
		filterCheckBox.setToolTipText(Captions.TOOLS_EXPORT_CHECKBOX_FILTER_TT);
		
		JLabel userOptionsLabel = new JLabel(Captions.TOOLS_EXPORT_LABEL_USER_OPTIONS + ":");
		
		exportUserOptionsButton = new JButton(Captions.TOOLS_EXPORT_BUTTON_USER_OPTIONS_EXPORT);
		exportUserOptionsButton.setToolTipText(Captions.TOOLS_EXPORT_BUTTON_USER_OPTIONS_EXPORT_TT);
		exportUserOptionsButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				exportUserOptions();
			}
		});
		
		importUserOptionsButton = new JButton(Captions.TOOLS_EXPORT_BUTTON_USER_OPTIONS_IMPORT);
		importUserOptionsButton.setToolTipText(Captions.TOOLS_EXPORT_BUTTON_USER_OPTIONS_IMPORT_TT);
		importUserOptionsButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				importUserOptions();
			}
		});
		
		clearUserOptionsButton = new JButton(Captions.TOOLS_EXPORT_BUTTON_USER_OPTIONS_CLEAR);
		clearUserOptionsButton.setToolTipText(Captions.TOOLS_EXPORT_BUTTON_USER_OPTIONS_CLEAR_TT);
		clearUserOptionsButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				clearUserOptions();
			}
		});
		
		userOptionsMessageLabel = UiUtil.createTemporaryMessageArea();
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(exportMemoToTxtFileButton)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(filterCheckBox, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addGroup(groupLayout.createSequentialGroup()
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING, false)
								.addComponent(userOptionsLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addGroup(groupLayout.createSequentialGroup()
									.addComponent(exportUserOptionsButton)
									.addPreferredGap(ComponentPlacement.RELATED)
									.addComponent(importUserOptionsButton)))
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(clearUserOptionsButton))
						.addComponent(notesLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(userOptionsMessageLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(notesLabel)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(exportMemoToTxtFileButton)
						.addComponent(filterCheckBox))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(userOptionsLabel)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(exportUserOptionsButton)
						.addComponent(importUserOptionsButton)
						.addComponent(clearUserOptionsButton))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(userOptionsMessageLabel)
					.addContainerGap())
		);
		setLayout(groupLayout);

	}

	private void exportUserOptions() {
		JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_EXPORT_FILE, USER_OPTIONS_FILE_DEFAULT);
		switch (fileChooser.showSaveDialog(UiUtil.getParentFrame(exportUserOptionsButton))) {
			case JFileChooser.APPROVE_OPTION:
				ConfigLogic.getInstance().exportUserOptions(fileChooser.getSelectedFile());
				UiUtil.showTemporaryMessage(userOptionsMessageLabel, Captions.MESSAGE_DONE);
				break;
			default:
				break;
		};
	}

	private void importUserOptions() {
		JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_IMPORT_FILE, USER_OPTIONS_FILE_DEFAULT);
		switch (fileChooser.showOpenDialog(UiUtil.getParentFrame(importUserOptionsButton))) {
			case JFileChooser.APPROVE_OPTION:
				ConfigLogic.getInstance().importUserOptions(fileChooser.getSelectedFile());
				Controller.getInstance().refreshUserOptionsPanel();
				UiUtil.showTemporaryMessage(userOptionsMessageLabel, Captions.MESSAGE_DONE);
				break;
			default:
				break;
		};
	}

	private void clearUserOptions() {
		if(UiUtil.getConfirmAnswerDefaultCancel(Captions.MESSAGE_CLEAR_USEROPTIONS, clearUserOptionsButton)) {
			ConfigLogic.getInstance().clearUserOptions();
			BurpApiClient.i().unloadExtension();
		}
	}

}
