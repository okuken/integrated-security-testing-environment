package okuken.iste.view.plugin;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import javax.swing.JTextField;

import burp.ITab;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.util.List;
import java.awt.event.ActionEvent;

public class PluginsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTabbedPane tabbedPane;

	public PluginsPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel configPanel = new JPanel();
		add(configPanel, BorderLayout.NORTH);
		
		JTextField jarFilePathTextField = new JTextField();
		configPanel.add(jarFilePathTextField);
		jarFilePathTextField.setColumns(30);
		
		JButton jarFileChooseButton = new JButton(Captions.FILECHOOSER);
		jarFileChooseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_PLUGIN_FILE);
				if (fileChooser.showOpenDialog(BurpUtil.getBurpSuiteJFrame()) == JFileChooser.APPROVE_OPTION) {
					jarFilePathTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
				}
			}
		});
		configPanel.add(jarFileChooseButton);
		
		JButton loadButton = new JButton(Captions.PLUGINS_BUTTON_LOAD_JAR);
		loadButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				Controller.getInstance().loadPlugin(jarFilePathTextField.getText());
			}
		});
		configPanel.add(loadButton);
		
		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);

	}

	public void addPluginTabs(List<ITab> pluginTabs) {
		pluginTabs.forEach(tab -> {
			tabbedPane.addTab(tab.getTabCaption(), tab.getUiComponent());
		});
	}

}
