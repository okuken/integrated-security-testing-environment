package okuken.iste.plugin;

import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

import com.google.common.collect.Lists;

import okuken.iste.plugin.api.IIsteContextMenuFactory;

public class PluginPopupMenuListener implements PopupMenuListener {

	private List<IIsteContextMenuFactory> isteContextMenuFactories = Lists.newArrayList();

	private JPopupMenu popupMenu;
	private JPopupMenu.Separator pluginMenuItemsStartSeparator;

	private List<JMenuItem> pluginMenuItems;

	public PluginPopupMenuListener(JPopupMenu popupMenu, JPopupMenu.Separator pluginMenuItemsStartSeparator) {
		this.popupMenu = popupMenu;
		this.pluginMenuItemsStartSeparator = pluginMenuItemsStartSeparator;
	}

	@Override
	public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
		if(isteContextMenuFactories.isEmpty()) {
			pluginMenuItemsStartSeparator.setVisible(false);
			return;
		}

		pluginMenuItems = isteContextMenuFactories.stream().flatMap(factory -> PluginUtil.createJMenuItems(factory).stream()).collect(Collectors.toList());
		if(pluginMenuItems.isEmpty()) {
			pluginMenuItemsStartSeparator.setVisible(false);
			return;
		}

		pluginMenuItemsStartSeparator.setVisible(true);
		var startIndex = popupMenu.getComponentIndex(pluginMenuItemsStartSeparator) + 1;
		for(int i = 0; i < pluginMenuItems.size(); i++) {
			popupMenu.add(pluginMenuItems.get(i), startIndex + i);
		}
	}

	@Override
	public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
		if(pluginMenuItems == null) {
			return;
		}
		pluginMenuItems.stream().forEach(pluginMenuItem -> popupMenu.remove(pluginMenuItem));
		pluginMenuItems = null;
	}

	@Override
	public void popupMenuCanceled(PopupMenuEvent e) {}


	public void addIsteContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		this.isteContextMenuFactories.addAll(isteContextMenuFactories);
	}

	public void removeIsteContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		this.isteContextMenuFactories.removeAll(isteContextMenuFactories);
	}

}
