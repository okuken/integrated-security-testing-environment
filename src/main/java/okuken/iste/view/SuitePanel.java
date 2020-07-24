package okuken.iste.view;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import javax.swing.JSplitPane;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Positions;
import okuken.iste.controller.Controller;
import okuken.iste.view.auth.AuthPanel;
import okuken.iste.view.header.MainHeaderPanel;
import okuken.iste.view.memo.MessageMemoPanel;
import okuken.iste.view.memo.ProjectMemoPanel;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.table.MessageTablePanel;
import okuken.iste.view.option.UserOptionsPanel;
import okuken.iste.view.repeater.RepeatMasterPanel;
import okuken.iste.view.repeater.RepeaterPanel;
import okuken.iste.view.tool.ExportToolsPanel;

import java.awt.GridLayout;

public class SuitePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JSplitPane mainSplitPane;
	private JSplitPane mainLeftSplitPane;
	private JSplitPane mainRightSplitPane;

	private RepeaterPanel repeaterPanel;

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
		
		mainSplitPane = new JSplitPane();
		mainSplitPane.setResizeWeight(1.0);
		mainPanel.add(mainSplitPane);
		
		JPanel mainLeftPanel = new JPanel();
		mainSplitPane.setLeftComponent(mainLeftPanel);
		mainLeftPanel.setLayout(new BorderLayout(0, 0));
		
		mainLeftSplitPane = new JSplitPane();
		mainLeftSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		mainLeftPanel.add(mainLeftSplitPane);
		
		JPanel messageTablePanel = new MessageTablePanel();
		mainLeftSplitPane.setLeftComponent(messageTablePanel);
		
		JTabbedPane messageDetailTabbedPane = new JTabbedPane(JTabbedPane.TOP);
		mainLeftSplitPane.setRightComponent(messageDetailTabbedPane);
		
		MessageEditorPanel orgMessageEditorPanel = new MessageEditorPanel();
		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_ORIGINAL, null, orgMessageEditorPanel, null);
		Controller.getInstance().setOrgMessageEditorPanel(orgMessageEditorPanel);
		
		RepeatMasterPanel repeatMasterPanel = new RepeatMasterPanel();
		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_REPEAT_MASTER, null, repeatMasterPanel, null);
		Controller.getInstance().setRepeatMasterPanel(repeatMasterPanel);
		
		repeaterPanel = new RepeaterPanel();
		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_REPEAT, null, repeaterPanel, null);
		Controller.getInstance().setRepeaterPanel(repeaterPanel);
		
		JPanel mainRightPanel = new JPanel();
		mainSplitPane.setRightComponent(mainRightPanel);
		mainRightPanel.setLayout(new BorderLayout(0, 0));
		
		mainRightSplitPane = new JSplitPane();
		mainRightSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		mainRightPanel.add(mainRightSplitPane);
		
		JPanel messageMemoPanel = new MessageMemoPanel();
		mainRightSplitPane.setLeftComponent(messageMemoPanel);
		
		JPanel messageAttrMemoPanel = new JPanel();
		mainRightSplitPane.setRightComponent(messageAttrMemoPanel);
		
		JPanel projectMemoPanel = new ProjectMemoPanel();
		mainTabbedPane.addTab(Captions.TAB_MEMO, null, projectMemoPanel, null);
		
		AuthPanel authPanel = new AuthPanel();
		mainTabbedPane.addTab(Captions.TAB_AUTH, null, authPanel, null);
		Controller.getInstance().setAuthPanel(authPanel);
		
		JPanel toolsPanel = new JPanel();
		mainTabbedPane.addTab(Captions.TAB_TOOLS, null, toolsPanel, null);
		toolsPanel.setLayout(new GridLayout(5, 1, 0, 0));
		
		JPanel exportToolPanel = new ExportToolsPanel();
		toolsPanel.add(exportToolPanel);
		
		JPanel optionsPanel = new JPanel();
		mainTabbedPane.addTab(Captions.TAB_OPTIONS, null, optionsPanel, null);
		optionsPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel userOptionsPanel = new UserOptionsPanel();
		optionsPanel.add(userOptionsPanel, BorderLayout.CENTER);
		
		
		SwingUtilities.invokeLater(() -> {
			initDividerLocation();
		});
	}

	public void initDividerLocation() {
		mainSplitPane.setDividerLocation(Positions.DIVIDER_LOCATION_MAIN);
		mainLeftSplitPane.setDividerLocation(Positions.DIVIDER_LOCATION_MAIN_LEFT);
		mainRightSplitPane.setDividerLocation(Positions.DIVIDER_LOCATION_MAIN_RIGHT);

		repeaterPanel.initDividerLocation();
	}

}