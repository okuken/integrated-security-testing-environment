package okuken.iste.plugin;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import burp.IBurpExtender;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;

public class PluginManager {

	private static final PluginManager instance = new PluginManager();

	private static final String PLUGIN_CLASS_NAME = "burp.IstePlugin"; // [CAUTION] If plugin class name is burp.BurpExtender, it finds ISTE itself because parent classLoader first.

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

		//TODO: sync
		try {
			var pluginJarFile = new File(pluginJarFilePath);
			var classLoader = new URLClassLoader(null, new URL[]{pluginJarFile.toURI().toURL()}, getClass().getClassLoader());
			classLoaders.put(pluginJarFilePath, classLoader);

			Class<?> pluginClass = classLoader.loadClass(PLUGIN_CLASS_NAME);
			var plugin = (IBurpExtender)pluginClass.getDeclaredConstructor().newInstance();

			var pluginCallbacks = new PluginCallbacks(pluginJarFile.getName());
			plugin.registerExtenderCallbacks(pluginCallbacks);

			if(pluginCallbacks.getPluginTabs() != null) {
				Controller.getInstance().addPluginTabs(pluginCallbacks.getPluginTabs());
			}
			if(pluginCallbacks.getPluginContextMenuFactories() != null) {
				Controller.getInstance().addPluginContextMenuFactories(pluginCallbacks.getPluginContextMenuFactories());
			}

			var ret = new PluginInfo();
			ret.setLoadInfo(new PluginLoadInfo(pluginJarFilePath, true));
			ret.setPluginName(Optional.ofNullable(pluginCallbacks.getPluginName()).orElse(""));
			ret.setPluginContextMenuFactories(pluginCallbacks.getPluginContextMenuFactories());
			ret.setPluginTabs(pluginCallbacks.getPluginTabs());
			ret.setPluginStateListener(pluginCallbacks.getPluginStateListener());

			loadedPluginInfos.add(ret);

			return ret;

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public void unload(PluginInfo pluginInfo) {
		pluginInfo.getLoadInfo().setLoaded(false);

		unloadImpl(pluginInfo);
		loadedPluginInfos.remove(pluginInfo);

		try {
			var key = pluginInfo.getLoadInfo().getJarFilePath();
			classLoaders.get(key).close();
			classLoaders.remove(key);
		} catch (IOException e) {
			BurpUtil.printStderr(e);
		}
	}

	private void unloadImpl(PluginInfo pluginInfo) {
		if(pluginInfo.getPluginStateListener() != null) {
			pluginInfo.getPluginStateListener().extensionUnloaded();
		}

		if(pluginInfo.getPluginContextMenuFactories() != null) {
			Controller.getInstance().removePluginContextMenuFactories(pluginInfo.getPluginContextMenuFactories());
		}
		if(pluginInfo.getPluginTabs() != null) {
			Controller.getInstance().removePluginTabs(pluginInfo.getPluginTabs());
		}
	}

	public void unloadAllPlugins() {
		loadedPluginInfos.forEach(pluginInfo -> {
			unloadImpl(pluginInfo);
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
