package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import okuken.iste.consts.Captions;

import java.awt.BorderLayout;

public class OptionsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public OptionsPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);
		
		JPanel projectOptionsPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_OPTIONS_PROJECT_OPTIONS, null, projectOptionsPanel, null);
		
		JPanel userOptionsPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_OPTIONS_USER_OPTIONS, null, userOptionsPanel, null);
		userOptionsPanel.setLayout(new BorderLayout(0, 0));
		
		JTabbedPane userOptionsTabbedPane = new JTabbedPane(JTabbedPane.TOP);
		userOptionsPanel.add(userOptionsTabbedPane);
		
		JPanel templatePanel = new UserOptionsTemplatePanel();
		userOptionsTabbedPane.addTab(Captions.TAB_OPTIONS_USER_OPTIONS_TEMPLATE, null, templatePanel, null);
		
		JPanel miscPanel = new UserOptionsMiscPanel();
		userOptionsTabbedPane.addTab(Captions.TAB_OPTIONS_USER_OPTIONS_MISC, null, miscPanel, null);
		
	}

}
