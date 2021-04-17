package okuken.iste.plugin.api;

public interface IIstePlugin {
	void registerCallbacks(IIstePluginCallbacks callbacks);
	void unloaded();
}
