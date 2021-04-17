package okuken.iste.plugin;

import java.io.OutputStream;
import java.util.List;

import com.google.common.collect.Lists;

import okuken.iste.plugin.api.IIsteContextMenuFactory;
import okuken.iste.plugin.api.IIstePluginCallbacks;
import okuken.iste.plugin.api.IIstePluginTab;
import okuken.iste.util.BurpUtil;

class PluginCallbacks implements IIstePluginCallbacks {

	private String pluginName;
	private List<IIsteContextMenuFactory> isteContextMenuFactories = Lists.newArrayList();
	private List<IIstePluginTab> pluginTabs = Lists.newArrayList();

	String getPluginName() {
		return pluginName;
	}
	List<IIsteContextMenuFactory> getIsteContextMenuFactories() {
		return isteContextMenuFactories;
	}
	List<IIstePluginTab> getPluginTabs() {
		return pluginTabs;
	}

	@Override
	public void setIstePluginName(String name) {
		pluginName = name;
	}

	@Override
	public void registerIsteContextMenuFactory(IIsteContextMenuFactory factory) {
		isteContextMenuFactories.add(factory);
	}

	@Override
	public void removeIsteContextMenuFactory(IIsteContextMenuFactory factory) {
		isteContextMenuFactories.remove(factory);
	}

	@Override
	public void addIstePluginTab(IIstePluginTab tab) {
		pluginTabs.add(tab);
	}

	@Override
	public void removeIstePluginTab(IIstePluginTab tab) {
		pluginTabs.remove(tab);
	}

	@Override
	public void saveIstePluginProjectOption(String name, String value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String loadIstePluginProjectOption(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void saveIstePluginUserOption(String name, String value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String loadIstePluginUserOption(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OutputStream getStdout() {
		return BurpUtil.getCallbacks().getStdout();
	}

	@Override
	public OutputStream getStderr() {
		return BurpUtil.getCallbacks().getStderr();
	}

}
