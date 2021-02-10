package okuken.iste.view.tool;

import javax.swing.JPanel;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JCheckBox;

public class ExportToolsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JCheckBox filterCheckBox;

	public ExportToolsPanel() {
		FlowLayout flowLayout = (FlowLayout) getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		
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
		add(exportMemoToTxtFileButton);
		
		filterCheckBox = new JCheckBox(Captions.TOOLS_EXPORT_CHECKBOX_FILTER);
		add(filterCheckBox);

	}

}
