package okuken.iste.view;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import javax.swing.JSplitPane;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.view.header.MainHeaderPanel;
import okuken.iste.view.memo.MessageMemoPanel;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.table.MessageTablePanel;
import okuken.iste.view.option.TestPanel;
import okuken.iste.view.option.UserOptionsPanel;

public class SuitePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public SuitePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane mainTabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(mainTabbedPane);
		Controller.getInstance().setMainTabbedPane(mainTabbedPane);
		
		JPanel mainPanel = new JPanel();
		mainTabbedPane.addTab(Captions.TAB_MAIN, null, mainPanel, null);
		mainPanel.setLayout(new BorderLayout(0, 0));
		Controller.getInstance().setMainPanel(mainPanel);
		
		JPanel mainHeaderPanel = new MainHeaderPanel();
		mainPanel.add(mainHeaderPanel, BorderLayout.NORTH);
		
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
		
		JPanel messageMemoPanel = new MessageMemoPanel();
		mainRightSplitPane.setLeftComponent(messageMemoPanel);
		
		JPanel messageAttrMemoPanel = new JPanel();
		mainRightSplitPane.setRightComponent(messageAttrMemoPanel);
		
		JPanel optionsPanel = new JPanel();
		mainTabbedPane.addTab(Captions.TAB_OPTIONS, null, optionsPanel, null);
		optionsPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel userOptionsPanel = new UserOptionsPanel();
		optionsPanel.add(userOptionsPanel, BorderLayout.CENTER);
		
		JPanel panel_1 = new TestPanel();
		optionsPanel.add(panel_1, BorderLayout.NORTH);

	}
}