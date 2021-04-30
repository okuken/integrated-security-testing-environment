package okuken.iste.plugin;

import java.util.List;

import okuken.iste.plugin.api.IIsteContextMenuFactory;
import okuken.iste.plugin.api.IIstePlugin;
import okuken.iste.plugin.api.IIstePluginTab;

public class PluginInfo {

	private PluginLoadInfo loadInfo;
	private IIstePlugin plugin;

	private String pluginName;
	private List<IIsteContextMenuFactory> isteContextMenuFactories;
	private List<IIsteContextMenuFactory> isteRepeaterContextMenuFactories;
	private List<IIstePluginTab> pluginTabs;

	public PluginInfo(PluginLoadInfo loadInfo) {
		this.loadInfo = loadInfo;
	}

	public PluginLoadInfo getLoadInfo() {
		return loadInfo;
	}
	public void setLoadInfo(PluginLoadInfo pluginLoadInfo) {
		this.loadInfo = pluginLoadInfo;
	}
	public IIstePlugin getPlugin() {
		return plugin;
	}
	public void setPlugin(IIstePlugin plugin) {
		this.plugin = plugin;
	}
	public String getPluginName() {
		return pluginName;
	}
	public void setPluginName(String pluginName) {
		this.pluginName = pluginName;
	}
	public List<IIsteContextMenuFactory> getIsteContextMenuFactories() {
		return isteContextMenuFactories;
	}
	public void setIsteContextMenuFactories(List<IIsteContextMenuFactory> isteContextMenuFactories) {
		this.isteContextMenuFactories = isteContextMenuFactories;
	}
	public List<IIsteContextMenuFactory> getIsteRepeaterContextMenuFactories() {
		return isteRepeaterContextMenuFactories;
	}
	public void setIsteRepeaterContextMenuFactories(
			List<IIsteContextMenuFactory> isteRepeaterContextMenuFactories) {
		this.isteRepeaterContextMenuFactories = isteRepeaterContextMenuFactories;
	}
	public List<IIstePluginTab> getPluginTabs() {
		return pluginTabs;
	}
	public void setPluginTabs(List<IIstePluginTab> pluginTabs) {
		this.pluginTabs = pluginTabs;
	}

}
