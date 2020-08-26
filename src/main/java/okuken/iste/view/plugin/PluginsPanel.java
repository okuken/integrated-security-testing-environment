package okuken.iste.view.plugin;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JTextField;

import burp.ITab;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.plugin.PluginInfo;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.event.ActionListener;
import java.util.List;
import java.awt.event.ActionEvent;
import javax.swing.JSplitPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import com.google.common.collect.Lists;

public class PluginsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTabbedPane tabbedPane;
	private JTable table;
	private DefaultTableModel tableModel;

	private List<PluginInfo> pluginInfos = Lists.newArrayList();

	@SuppressWarnings("serial")
	public PluginsPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPane = new JSplitPane();
		add(splitPane);
		
		JPanel configPanel = new JPanel();
		splitPane.setLeftComponent(configPanel);
		configPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel configHeaderPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) configHeaderPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		configPanel.add(configHeaderPanel, BorderLayout.NORTH);
		
		JTextField jarFilePathTextField = new JTextField();
		configHeaderPanel.add(jarFilePathTextField);
		jarFilePathTextField.setColumns(30);
		
		JButton jarFileChooseButton = new JButton(Captions.FILECHOOSER);
		configHeaderPanel.add(jarFileChooseButton);
		
		JButton addButton = new JButton(Captions.PLUGINS_BUTTON_ADD_PLUGIN);
		configHeaderPanel.add(addButton);
		
		JScrollPane pluginTableScrollPane = new JScrollPane();
		configPanel.add(pluginTableScrollPane, BorderLayout.CENTER);
		
		table = new JTable();
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"Loaded", "Name", "Jar file"
			}
		) {
			Class<?>[] columnTypes = new Class[] {
				Boolean.class, Object.class, Object.class
			};
			@Override
			public Class<?> getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}
			boolean[] columnEditables = new boolean[] {
					true, false, false
			};
			@Override
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
			@Override
			public void setValueAt(Object val, int rowIndex, int columnIndex) {
				loadOrUnloadPlugin(rowIndex, (Boolean)val);
			}
		});
		table.getColumnModel().getColumn(0).setPreferredWidth(50);
		table.getColumnModel().getColumn(1).setPreferredWidth(100);
		table.getColumnModel().getColumn(2).setPreferredWidth(300);
		pluginTableScrollPane.setViewportView(table);
		
		UiUtil.setupCtrlCAsCopyCell(table);
		
		tableModel = (DefaultTableModel) table.getModel();
		
		addButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ev) {
				addPlugin(jarFilePathTextField.getText());
			}
		});
		jarFileChooseButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_PLUGIN_FILE);
				if (fileChooser.showOpenDialog(BurpUtil.getBurpSuiteJFrame()) == JFileChooser.APPROVE_OPTION) {
					jarFilePathTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
				}
			}
		});
		
		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		splitPane.setRightComponent(tabbedPane);

	}

	private void addPlugin(String jarFilePath) {
		var pluginInfo = Controller.getInstance().loadPlugin(jarFilePath);
		pluginInfos.add(pluginInfo);
		tableModel.addRow(convertPluginInfoToObjectArray(pluginInfo, true));
	}

	private void loadOrUnloadPlugin(int pluginIndex, boolean load) {
		if(load) {
			var newPluginInfo = Controller.getInstance().loadPlugin(pluginInfos.get(pluginIndex).getJarFilePath());

			pluginInfos.remove(pluginIndex);
			pluginInfos.add(pluginIndex, newPluginInfo);

			tableModel.removeRow(pluginIndex);
			tableModel.insertRow(pluginIndex, convertPluginInfoToObjectArray(newPluginInfo, load));

		} else {
			Controller.getInstance().unloadPlugin(pluginInfos.get(pluginIndex));

			tableModel.removeRow(pluginIndex);
			tableModel.insertRow(pluginIndex, convertPluginInfoToObjectArray(pluginInfos.get(pluginIndex), load));
		}
	}

	private Object[] convertPluginInfoToObjectArray(PluginInfo pluginInfo, boolean load) {
		return new Object[] {load, pluginInfo.getPluginName(), pluginInfo.getJarFilePath()};
	}

	public void addPluginTabs(List<ITab> pluginTabs) {
		pluginTabs.forEach(tab -> {
			if(tabbedPane.indexOfTab(tab.getTabCaption()) >= 0) {
				throw new RuntimeException("Duplicated plugin tab name: " + tab.getTabCaption());
			}
			tabbedPane.addTab(tab.getTabCaption(), tab.getUiComponent());
		});
	}

	public void removePluginTabs(List<ITab> pluginTabs) {
		pluginTabs.forEach(tab -> {
			var tabIndex = tabbedPane.indexOfTab(tab.getTabCaption());
			if(tabIndex < 0) {
				throw new RuntimeException("Not found plugin tab name: " + tab.getTabCaption());
			}
			tabbedPane.removeTabAt(tabIndex);
		});
	}

}
