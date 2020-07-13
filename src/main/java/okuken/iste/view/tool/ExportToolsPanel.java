package okuken.iste.view.tool;

import javax.swing.JPanel;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class ExportToolsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public ExportToolsPanel() {
		FlowLayout flowLayout = (FlowLayout) getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		
		JButton exportMemoToTxtFileButton = new JButton(Captions.TOOLS_EXPORT_BUTTON_EXPORT_MEMO_TO_TXT_FILE);
		exportMemoToTxtFileButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = FileUtil.createSingleFileChooser("");
				switch (fileChooser.showSaveDialog(BurpUtil.getBurpSuiteJFrame())) {
					case JFileChooser.APPROVE_OPTION:
						Controller.getInstance().exportMemoToTxtFile(fileChooser.getSelectedFile());
						break;
					default:
						break;
				};
			}
		});
		add(exportMemoToTxtFileButton);

	}

}
