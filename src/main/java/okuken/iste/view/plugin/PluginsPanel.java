package okuken.iste.view.plugin;

import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JTextField;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.plugin.PluginInfo;
import okuken.iste.plugin.PluginLoadInfo;
import okuken.iste.plugin.api.IIstePluginTab;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;

import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;
import javax.swing.JSplitPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;

public class PluginsPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTextField jarFilePathTextField;
	private JButton jarFileChooseButton;
	private JButton addButton;
	private JPopupMenu popupMenu;

	private JTabbedPane tabbedPane;
	private JTable table;
	private DefaultTableModel tableModel;

	private List<PluginInfo> pluginInfos = Lists.newArrayList();

	private boolean existPluginInClasspath;

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
		
		jarFilePathTextField = new JTextField();
		configHeaderPanel.add(jarFilePathTextField);
		jarFilePathTextField.setColumns(30);
		
		jarFileChooseButton = new JButton(Captions.FILECHOOSER);
		configHeaderPanel.add(jarFileChooseButton);
		
		addButton = new JButton(Captions.PLUGINS_BUTTON_ADD_PLUGIN);
		configHeaderPanel.add(addButton);
		
		JScrollPane pluginTableScrollPane = new JScrollPane();
		configPanel.add(pluginTableScrollPane, BorderLayout.CENTER);
		
		table = new JTable() {
			@Override
			public void changeSelection(int row, int col, boolean toggle, boolean extend) {
				super.changeSelection(row, col, toggle, extend);
				jarFilePathTextField.setText(pluginInfos.get(row).getLoadInfo().getJarFilePath());
			}
		};
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
		
		popupMenu = createPopupMenu();
		table.setComponentPopupMenu(popupMenu);
		
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
				JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_PLUGIN_FILE, jarFilePathTextField.getText());
				if (fileChooser.showOpenDialog(UiUtil.getParentFrame(jarFileChooseButton)) == JFileChooser.APPROVE_OPTION) {
					jarFilePathTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
				}
			}
		});
		
		tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		splitPane.setRightComponent(tabbedPane);

	}

	private JPopupMenu createPopupMenu() {
		var menu = new JPopupMenu();
		var menuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_DELETE_ITEM);
		menuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				removeSelectedPlugins();
			}
		});
		menu.add(menuItem);
		return menu;
	}

	private void addPlugin(String jarFilePath) {
		if(StringUtils.isBlank(jarFilePath) ||
			pluginInfos.stream().filter(info -> info.getLoadInfo().getJarFilePath().equals(jarFilePath)).findAny().isPresent()) {
			return;
		}

		addPluginImpl(jarFilePath, true);
		saveAsUserOption();
	}

	private void addPluginImpl(String jarFilePath, boolean load) {
		PluginInfo pluginInfo;
		if(load) {
			pluginInfo = Controller.getInstance().loadPlugin(jarFilePath);
		} else {
			pluginInfo = new PluginInfo(new PluginLoadInfo(jarFilePath, load));
		}
		addPluginInfo(pluginInfo);
	}

	private void addPluginInfo(PluginInfo pluginInfo) {
		pluginInfos.add(pluginInfo);
		tableModel.addRow(convertPluginInfoToObjectArray(pluginInfo));
	}

	private boolean addPluginFromClasspath() {
		var pluginInfo = Controller.getInstance().loadPluginFromClasspath();
		if(pluginInfo == null) {
			return false;
		}

		addPluginInfo(pluginInfo);
		return true;
	}

	private void removeSelectedPlugins() {
		var selectedRowIndexs = Arrays.stream(table.getSelectedRows()).mapToObj(Integer::valueOf).collect(Collectors.toList());
		Collections.reverse(selectedRowIndexs);

		for(var rowIndex: selectedRowIndexs) {
			if(pluginInfos.get(rowIndex).getLoadInfo().isLoaded()) {
				loadOrUnloadPlugin(rowIndex, false);
			}
			removePluginInfo(rowIndex);
		}

		saveAsUserOption();
	}

	private void removePluginInfo(int index) {
		pluginInfos.remove(index);
		tableModel.removeRow(index);
	}

	private void loadOrUnloadPlugin(int pluginIndex, boolean load) {
		if(load) {
			var newPluginInfo = loadPluginImpl(pluginInfos.get(pluginIndex));

			pluginInfos.remove(pluginIndex);
			pluginInfos.add(pluginIndex, newPluginInfo);

			tableModel.removeRow(pluginIndex);
			tableModel.insertRow(pluginIndex, convertPluginInfoToObjectArray(newPluginInfo));

		} else {
			Controller.getInstance().unloadPlugin(pluginInfos.get(pluginIndex));

			tableModel.removeRow(pluginIndex);
			tableModel.insertRow(pluginIndex, convertPluginInfoToObjectArray(pluginInfos.get(pluginIndex)));
		}

		saveAsUserOption();
	}
	private PluginInfo loadPluginImpl(PluginInfo pluginInfo) {
		if(pluginInfo.isFromClasspath()) {
			return Controller.getInstance().loadPluginFromClasspath();
		}
		return Controller.getInstance().loadPlugin(pluginInfo.getLoadInfo().getJarFilePath());
	}

	private Object[] convertPluginInfoToObjectArray(PluginInfo pluginInfo) {
		return new Object[] {
				pluginInfo.getLoadInfo().isLoaded(),
				pluginInfo.getPluginName(),
				pluginInfo.isFromClasspath() ? Captions.PLUGINS_LOAD_FROM_CLASSPATH : pluginInfo.getLoadInfo().getJarFilePath()};
	}

	private void saveAsUserOption() {
		if(existPluginInClasspath) {
			return;
		}
		ConfigLogic.getInstance().savePlugins(pluginInfos.stream().filter(pluginInfo -> !pluginInfo.isFromClasspath()).map(PluginInfo::getLoadInfo).collect(Collectors.toList()));
	}

	public void loadUserOption() {
		existPluginInClasspath = addPluginFromClasspath();
		if(existPluginInClasspath) {
			disableControls();
			return;
		}

		var pluginLoadInfos = ConfigLogic.getInstance().getUserOptions().getPlugins();
		if(pluginLoadInfos == null) {
			return;
		}

		pluginLoadInfos.stream().forEach(pluginLoafInfo -> {
			addPluginImpl(pluginLoafInfo.getJarFilePath(), pluginLoafInfo.isLoaded());
		});
	}

	private void disableControls() {
		jarFilePathTextField.setEnabled(false);
		jarFileChooseButton.setEnabled(false);
		addButton.setEnabled(false);
		Arrays.stream(popupMenu.getComponents()).forEach(c -> c.setEnabled(false));
	}

	public void addPluginTabs(List<IIstePluginTab> pluginTabs) {
		pluginTabs.forEach(tab -> {
			if(tabbedPane.indexOfTab(tab.getTabCaption()) >= 0) {
				throw new RuntimeException("Duplicated plugin tab name: " + tab.getTabCaption());
			}
			tabbedPane.addTab(tab.getTabCaption(), tab.getUiComponent());
		});
	}

	public void removePluginTabs(List<IIstePluginTab> pluginTabs) {
		pluginTabs.forEach(tab -> {
			var tabIndex = tabbedPane.indexOfTab(tab.getTabCaption());
			if(tabIndex < 0) {
				throw new RuntimeException("Not found plugin tab name: " + tab.getTabCaption());
			}
			tabbedPane.removeTabAt(tabIndex);
		});
	}

}
