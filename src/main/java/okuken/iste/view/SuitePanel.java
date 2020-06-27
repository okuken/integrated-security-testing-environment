package okuken.iste.view;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import javax.swing.JSplitPane;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;

import okuken.iste.consts.Captions;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.table.MessageTablePanel;

public class SuitePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public SuitePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);
		
		JPanel mainPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_MAIN, null, mainPanel, null);
		mainPanel.setLayout(new BorderLayout(0, 0));
		
		JSplitPane mainSplitPane = new JSplitPane();
		mainPanel.add(mainSplitPane);
		
		JPanel mainLeftPanel = new JPanel();
		mainSplitPane.setLeftComponent(mainLeftPanel);
		mainLeftPanel.setLayout(new BorderLayout(0, 0));
		
		JSplitPane mainLeftSplitPane = new JSplitPane();
		mainLeftSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		mainLeftPanel.add(mainLeftSplitPane);
		
		JPanel messageTablePanel = new MessageTablePanel();
		mainLeftSplitPane.setLeftComponent(messageTablePanel);
		
		JPanel messageEditorPanel = new MessageEditorPanel();
		mainLeftSplitPane.setRightComponent(messageEditorPanel);
		
		JPanel panel = new JPanel();
		mainLeftPanel.add(panel, BorderLayout.NORTH);
		
		JPanel mainRightPanel = new JPanel();
		mainSplitPane.setRightComponent(mainRightPanel);
		mainRightPanel.setLayout(new BorderLayout(0, 0));
		
		JSplitPane mainRightSplitPane = new JSplitPane();
		mainRightSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		mainRightPanel.add(mainRightSplitPane);
		
		JPanel messageMemoPanel = new JPanel();
		mainRightSplitPane.setLeftComponent(messageMemoPanel);
		
		JPanel messageAttrMemoPanel = new JPanel();
		mainRightSplitPane.setRightComponent(messageAttrMemoPanel);
		
		JPanel optionsPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_OPTIONS, null, optionsPanel, null);
		GroupLayout gl_optionsPanel = new GroupLayout(optionsPanel);
		gl_optionsPanel.setHorizontalGroup(
			gl_optionsPanel.createParallelGroup(Alignment.LEADING)
				.addGap(0, 445, Short.MAX_VALUE)
		);
		gl_optionsPanel.setVerticalGroup(
			gl_optionsPanel.createParallelGroup(Alignment.LEADING)
				.addGap(0, 273, Short.MAX_VALUE)
		);
		optionsPanel.setLayout(gl_optionsPanel);

	}
}