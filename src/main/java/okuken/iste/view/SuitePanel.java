package okuken.iste.view;

import javax.swing.AbstractButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.google.common.collect.Lists;

import java.awt.BorderLayout;
import javax.swing.JSplitPane;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Positions;
import okuken.iste.controller.Controller;
import okuken.iste.util.UiUtil;
import okuken.iste.view.about.AboutPanel;
import okuken.iste.view.auth.AuthPanel;
import okuken.iste.view.header.MainHeaderPanel;
import okuken.iste.view.memo.MessageMemoPanel;
import okuken.iste.view.memo.ProjectMemoPanel;
import okuken.iste.view.message.editor.MessageEditorPanel;
import okuken.iste.view.message.table.MessageTablePanel;
import okuken.iste.view.option.OptionsPanel;
import okuken.iste.view.plugin.PluginsPanel;
import okuken.iste.view.repeater.RepeatMasterPanel;
import okuken.iste.view.repeater.RepeaterPanel;
import okuken.iste.view.tool.ToolsPanel;

import java.util.List;

public class SuitePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTabbedPane mainTabbedPane;
	private JFrame dockoutFrame;

	private MainHeaderPanel mainHeaderPanel;

	private JSplitPane mainSplitPane;
	private JSplitPane mainLeftSplitPane;
	private JSplitPane mainRightSplitPane;

	private RepeaterPanel repeaterPanel;

	@SuppressWarnings("serial")
	public SuitePanel() {
		setLayout(new BorderLayout(0, 0));
		
		mainTabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(mainTabbedPane);
		Controller.getInstance().setMainTabbedPane(mainTabbedPane);
		
		List<AbstractDockoutableTabPanel> dockoutableTabPanels = Lists.newArrayList();
		
		var mainPanel = new AbstractDockoutableTabPanel() {
			protected AbstractButton getDockoutButton() {
				return mainHeaderPanel.getDockoutButton();
			}
			protected String getTabName() {
				return Captions.TAB_MAIN;
			}
			protected int getTabIndex() {
				return 0;
			}
		};
		dockoutableTabPanels.add(mainPanel);
		mainTabbedPane.addTab(Captions.TAB_MAIN, null, mainPanel, null);
		mainPanel.setLayout(new BorderLayout(0, 0));
		Controller.getInstance().setMainPanel(mainPanel);
		
		mainHeaderPanel = new MainHeaderPanel();
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
		Controller.getInstance().setMessageDetailTabbedPane(messageDetailTabbedPane);
		
		MessageEditorPanel orgMessageEditorPanel = new MessageEditorPanel();
		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_ORIGINAL, null, orgMessageEditorPanel, null);
		Controller.getInstance().setOrgMessageEditorPanel(orgMessageEditorPanel);
		
		RepeatMasterPanel repeatMasterPanel = new RepeatMasterPanel();
		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_REPEAT_MASTER, null, repeatMasterPanel, null);
		Controller.getInstance().setRepeatMasterPanel(repeatMasterPanel);
		
		repeaterPanel = new RepeaterPanel();
		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_REPEAT, null, repeaterPanel, null);
		Controller.getInstance().setRepeaterPanel(repeaterPanel);
		
//		ChainRepeaterPanel chainRepeaterPanel = new ChainRepeaterPanel();
//		messageDetailTabbedPane.addTab(Captions.TAB_MAIN_MESSAGE_EDITOR_CHAIN, null, chainRepeaterPanel, null);
//		Controller.getInstance().setChainRepeaterPanel(chainRepeaterPanel);
		
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
		
		ProjectMemoPanel projectMemoPanel = new ProjectMemoPanel();
		mainTabbedPane.addTab(Captions.TAB_MEMO, null, projectMemoPanel, null);
		Controller.getInstance().setProjectMemoPanel(projectMemoPanel);
		
		AuthPanel authPanel = new AuthPanel();
		mainTabbedPane.addTab(Captions.TAB_AUTH, null, authPanel, null);
		Controller.getInstance().setAuthPanel(authPanel);
		
		JPanel toolsPanel = new ToolsPanel();
		mainTabbedPane.addTab(Captions.TAB_TOOLS, null, toolsPanel, null);
		
		JPanel optionsPanel = new OptionsPanel();
		mainTabbedPane.addTab(Captions.TAB_OPTIONS, null, optionsPanel, null);
		
		PluginsPanel pluginsPanel = new PluginsPanel();
		mainTabbedPane.addTab(Captions.TAB_PLUGINS, null, pluginsPanel, null);
		Controller.getInstance().setPluginsPanel(pluginsPanel);
		
		JPanel aboutPanel = new AboutPanel();
		mainTabbedPane.addTab(Captions.TAB_ABOUT, null, aboutPanel, null);
		
		mainTabbedPane.addTab(Captions.DOCKOUT, null);
		mainTabbedPane.setToolTipTextAt(getDockoutTabIndex(), Captions.DOCKOUT_TT);
		mainTabbedPane.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				if(mainTabbedPane.getSelectedIndex() == getDockoutTabIndex()) {
					dockoutOrDockin();
				}
			}
		});
		
		
		dockoutableTabPanels.forEach(panel -> {
			panel.setupDockout();
		});
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

	private int getDockoutTabIndex() {
		return mainTabbedPane.getTabCount() - 1;
	}
	private void setDockoutTabTitle(String title, String toolTip) {
		var dockoutTabIndex = getDockoutTabIndex();
		mainTabbedPane.setTitleAt(dockoutTabIndex, title);
		mainTabbedPane.setToolTipTextAt(dockoutTabIndex, toolTip);
	}
	private void dockoutOrDockin() {
		if (dockoutFrame == null) {
			dockoutFrame = UiUtil.dockout(Captions.EXTENSION_NAME_FULL, mainTabbedPane, we -> {dockin();});
			setDockoutTabTitle(Captions.DOCKIN, Captions.DOCKIN_TT);
			this.repaint();
			mainTabbedPane.setSelectedIndex(0);
		} else {
			dockin();
		}
	}
	private void dockin() {
		UiUtil.dockin(mainTabbedPane, this, dockoutFrame);
		dockoutFrame = null;
		setDockoutTabTitle(Captions.DOCKOUT, Captions.DOCKOUT_TT);
		mainTabbedPane.setSelectedIndex(0);
	}

}