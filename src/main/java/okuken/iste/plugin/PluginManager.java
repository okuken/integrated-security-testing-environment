package okuken.iste.plugin;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import okuken.iste.controller.Controller;
import okuken.iste.plugin.api.IIstePlugin;
import okuken.iste.util.BurpUtil;

public class PluginManager {

	private static final PluginManager instance = new PluginManager();

	private static final String PLUGIN_CLASS_NAME = "iste.IstePlugin";

	private Map<String, URLClassLoader> classLoaders = Maps.newConcurrentMap();
	private List<PluginInfo> loadedPluginInfos = Lists.newArrayList();

	private PluginManager() {}
	public static PluginManager getInstance() {
		return instance;
	}

	public PluginInfo load(String pluginJarFilePath) {
		if(classLoaders.containsKey(pluginJarFilePath)) {
			throw new IllegalArgumentException("Duplicated load: " + pluginJarFilePath);
		}

		var ret = new PluginInfo(new PluginLoadInfo(pluginJarFilePath, false));

		var pluginJarFile = new File(pluginJarFilePath);
		if(!pluginJarFile.exists()) {
			BurpUtil.printStderr("Plugin file does not exist: " + pluginJarFilePath);
			return ret;
		}

		URLClassLoader classLoader = null;
		try {
			classLoader = new URLClassLoader(null, new URL[]{pluginJarFile.toURI().toURL()}, getClass().getClassLoader());
		} catch (Exception e) {
			BurpUtil.printStderr("ClassLoader error. file: " + pluginJarFilePath);
			BurpUtil.printStderr(e);
			return ret;
		}
		classLoaders.put(pluginJarFilePath, classLoader);

		IIstePlugin plugin = null;
		try {
			var pluginClass = classLoader.loadClass(PLUGIN_CLASS_NAME);
			plugin = (IIstePlugin)pluginClass.getDeclaredConstructor().newInstance();
		} catch (Exception e) {
			BurpUtil.printStderr("Load plugin class error. file: " + pluginJarFilePath);
			BurpUtil.printStderr(e);
			closeClassLoader(pluginJarFilePath);
			return ret;
		}
		ret.setPlugin(plugin);

		return loadImpl(plugin, ret);
	}

	/**
	 * for debugging plugin
	 */
	public PluginInfo loadFromClasspath() {
		try {
			var pluginClass = Class.forName(PLUGIN_CLASS_NAME);
			var plugin = (IIstePlugin)pluginClass.getDeclaredConstructor().newInstance();

			var ret = new PluginInfo(new PluginLoadInfo("", false));
			ret.setFromClasspath(true);
			ret.setPlugin(plugin);

			return loadImpl(plugin, ret);

		} catch (ClassNotFoundException e) {
			return null; // general case
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			return null;
		}
	}

	private PluginInfo loadImpl(IIstePlugin plugin, PluginInfo ret) {
		try {
			var pluginCallbacks = new PluginCallbacks();
			plugin.registerCallbacks(pluginCallbacks);

			ret.setPluginName(Optional.ofNullable(pluginCallbacks.getPluginName()).orElse(""));
			ret.setIsteContextMenuFactories(pluginCallbacks.getIsteContextMenuFactories());
			ret.setIsteRepeaterContextMenuFactories(pluginCallbacks.getIsteRepeaterContextMenuFactories());
			ret.setPluginTabs(pluginCallbacks.getPluginTabs());

			Controller.getInstance().addPluginTabs(ret.getPluginTabs());
			Controller.getInstance().addIsteContextMenuFactories(ret.getIsteContextMenuFactories());
			Controller.getInstance().addIsteRepeaterContextMenuFactories(ret.getIsteRepeaterContextMenuFactories());

			ret.getLoadInfo().setLoaded(true);
			loadedPluginInfos.add(ret);
			return ret;

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			unload(ret);
			return ret;
		}
	}

	public void invokeProjectChanged() {
		loadedPluginInfos.forEach(pluginInfo -> {
			try {
				pluginInfo.getPlugin().projectChanged();
			} catch (Exception e) {
				BurpUtil.printStderr(e);
			}
		});
	}

	public void unload(PluginInfo pluginInfo) {
		pluginInfo.getLoadInfo().setLoaded(false);

		try {
			unloadImpl(pluginInfo);
		} catch (Exception e) {
			BurpUtil.printStderr(e);
		}
		loadedPluginInfos.remove(pluginInfo);

		if(pluginInfo.isFromClasspath()) {
			return;
		}
		closeClassLoader(pluginInfo.getLoadInfo().getJarFilePath());
	}

	private void unloadImpl(PluginInfo pluginInfo) {
		if(pluginInfo.getIsteRepeaterContextMenuFactories() != null) {
			Controller.getInstance().removeIsteRepeaterContextMenuFactories(pluginInfo.getIsteRepeaterContextMenuFactories());
		}
		if(pluginInfo.getIsteContextMenuFactories() != null) {
			Controller.getInstance().removeIsteContextMenuFactories(pluginInfo.getIsteContextMenuFactories());
		}
		if(pluginInfo.getPluginTabs() != null) {
			Controller.getInstance().removePluginTabs(pluginInfo.getPluginTabs());
		}

		pluginInfo.getPlugin().unloaded();
	}

	private void closeClassLoader(String key) {
		try {
			classLoaders.get(key).close();
		} catch (Exception e) {
			BurpUtil.printStderr(e);
		}
		classLoaders.remove(key);
	}

	public void unloadAllPlugins() {
		Collections.reverse(loadedPluginInfos);
		loadedPluginInfos.forEach(pluginInfo -> {
			try {
				unloadImpl(pluginInfo);
			} catch (Exception e) {
				BurpUtil.printEventLog(e.getMessage());
			}
		});
		loadedPluginInfos.clear();

		classLoaders.values().forEach(classLoader -> {
			try {
				classLoader.close();
			} catch (IOException e) {
				BurpUtil.printEventLog(e.getMessage());
			}
		});
		classLoaders.clear();
	}

}
