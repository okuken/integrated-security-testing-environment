package okuken.iste.plugin.api;

import java.io.OutputStream;

public interface IIstePluginCallbacks {

	void setIstePluginName(String name);

	void addIstePluginTab(IIstePluginTab tab);
	void removeIstePluginTab(IIstePluginTab tab);

	void registerIsteContextMenuFactory(IIsteContextMenuFactory factory);
	void removeIsteContextMenuFactory(IIsteContextMenuFactory factory);

	void saveIstePluginProjectOption(String name, String value);
	String loadIstePluginProjectOption(String name);

	void saveIstePluginUserOption(String name, String value);
	String loadIstePluginUserOption(String name);

	OutputStream getStdout();
	OutputStream getStderr();

}
