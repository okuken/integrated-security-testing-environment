package okuken.iste.plugin;

import java.io.OutputStream;
import java.util.List;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;

import okuken.iste.client.BurpApiClient;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.plugin.api.IIsteContextMenuFactory;
import okuken.iste.plugin.api.IIsteImportMessage;
import okuken.iste.plugin.api.IIstePluginCallbacks;
import okuken.iste.plugin.api.IIstePluginHelpers;
import okuken.iste.plugin.api.IIstePluginTab;

class PluginCallbacks implements IIstePluginCallbacks {

	private String pluginName;
	private List<IIsteContextMenuFactory> isteContextMenuFactories = Lists.newArrayList();
	private List<IIsteContextMenuFactory> isteRepeaterContextMenuFactories = Lists.newArrayList();
	private List<IIstePluginTab> pluginTabs = Lists.newArrayList();

	String getPluginName() {
		return pluginName;
	}
	List<IIsteContextMenuFactory> getIsteContextMenuFactories() {
		return isteContextMenuFactories;
	}
	List<IIsteContextMenuFactory> getIsteRepeaterContextMenuFactories() {
		return isteRepeaterContextMenuFactories;
	}
	List<IIstePluginTab> getPluginTabs() {
		return pluginTabs;
	}

	@Override
	public void setIstePluginName(String name) {
		pluginName = name;
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
	public void registerIsteContextMenuFactory(IIsteContextMenuFactory factory) {
		isteContextMenuFactories.add(factory);
	}
	@Override
	public void removeIsteContextMenuFactory(IIsteContextMenuFactory factory) {
		isteContextMenuFactories.remove(factory);
	}

	@Override
	public void registerIsteRepeaterContextMenuFactory(IIsteContextMenuFactory factory) {
		isteRepeaterContextMenuFactories.add(factory);
	}
	@Override
	public void removeIsteRepeaterContextMenuFactory(IIsteContextMenuFactory factory) {
		isteRepeaterContextMenuFactories.remove(factory);
	}

	@Override
	public void importIsteMessages(List<IIsteImportMessage> importMessages) {
		Controller.getInstance().addMessages(
				importMessages.stream().map(PluginUtil::convertIsteImportMessageToMessageDto).collect(Collectors.toList()));
	}

	@Override
	public void saveIstePluginProjectOption(String name, String value) {
		ConfigLogic.getInstance().savePluginProjectOption(pluginName, name, value);
	}
	@Override
	public String loadIstePluginProjectOption(String name) {
		return ConfigLogic.getInstance().getPluginProjectOption(pluginName, name);
	}

	@Override
	public void saveIstePluginUserOption(String name, String value) {
		throw new UnsupportedOperationException("not implemented yet");
	}
	@Override
	public String loadIstePluginUserOption(String name) {
		throw new UnsupportedOperationException("not implemented yet");
	}

	@Override
	public OutputStream getStdout() {
		return BurpApiClient.i().getStdout();
	}
	@Override
	public OutputStream getStderr() {
		return BurpApiClient.i().getStderr();
	}

	@Override
	public IIstePluginHelpers getHelpers() {
		return PluginHelpers.getInstance();
	}

}
