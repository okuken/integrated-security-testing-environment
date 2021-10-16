package okuken.iste.view.tool;

import javax.swing.JPanel;
import java.awt.BorderLayout;

import javax.swing.JTabbedPane;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;

public class ToolsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public ToolsPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane, BorderLayout.CENTER);
		Controller.getInstance().setToolsTabbedPane(tabbedPane);
		
		JPanel exportPanel = new ExportToolsPanel();
		tabbedPane.addTab(Captions.TAB_TOOLS_EXPORT, null, exportPanel, null);
		
//		JPanel bsqliPanel = new BlindSqlInjectionPanel();
//		tabbedPane.addTab(Captions.TAB_TOOLS_BSQLI, null, bsqliPanel, null);
		
	}

}
