package okuken.iste.plugin;

import com.google.gson.Gson;

import okuken.iste.plugin.api.IIstePluginHelpers;

public class PluginHelpers implements IIstePluginHelpers {

	private static final PluginHelpers instance = new PluginHelpers();
	private PluginHelpers() {}
	static PluginHelpers getInstance() {
		return instance;
	}

	@Override
	public <T> T fromJson(String json, Class<T> classOfT) {
		return (T)new Gson().fromJson(json, classOfT);
	}

	@Override
	public String toJson(Object src) {
		return new Gson().toJson(src);
	}

}
