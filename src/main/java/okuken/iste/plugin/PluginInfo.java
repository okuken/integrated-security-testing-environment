package okuken.iste.plugin;

import java.util.List;

import burp.IContextMenuFactory;
import burp.IExtensionStateListener;
import burp.ITab;

public class PluginInfo {

	private PluginLoadInfo loadInfo;

	private String pluginName;
	private List<IContextMenuFactory> pluginContextMenuFactories;
	private List<ITab> pluginTabs;
	private IExtensionStateListener pluginStateListener;

	public PluginInfo() {}
	public PluginInfo(PluginLoadInfo loadInfo) {
		this.loadInfo = loadInfo;
	}

	public PluginLoadInfo getLoadInfo() {
		return loadInfo;
	}
	public void setLoadInfo(PluginLoadInfo pluginLoadInfo) {
		this.loadInfo = pluginLoadInfo;
	}
	public String getPluginName() {
		return pluginName;
	}
	public void setPluginName(String pluginName) {
		this.pluginName = pluginName;
	}
	public List<IContextMenuFactory> getPluginContextMenuFactories() {
		return pluginContextMenuFactories;
	}
	public void setPluginContextMenuFactories(List<IContextMenuFactory> pluginContextMenuFactories) {
		this.pluginContextMenuFactories = pluginContextMenuFactories;
	}
	public List<ITab> getPluginTabs() {
		return pluginTabs;
	}
	public void setPluginTabs(List<ITab> pluginTabs) {
		this.pluginTabs = pluginTabs;
	}
	public IExtensionStateListener getPluginStateListener() {
		return pluginStateListener;
	}
	public void setPluginStateListener(IExtensionStateListener pluginStateListener) {
		this.pluginStateListener = pluginStateListener;
	}

}
