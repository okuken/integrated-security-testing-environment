package okuken.iste.plugin;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Map;

import com.google.common.collect.Maps;

import burp.IBurpExtender;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;

public class PluginManager {

	private static final PluginManager instance = new PluginManager();

	private static final String PLUGIN_CLASS_NAME = "burp.IstePlugin"; // [CAUTION] If plugin class name is burp.BurpExtender, it finds ISTE itself because parent classLoader first.

	private Map<String, URLClassLoader> classLoaders = Maps.newConcurrentMap();

	private PluginManager() {}
	public static PluginManager getInstance() {
		return instance;
	}

	public void load(String pluginJarFilePath) {
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

			if(pluginCallbacks.getPluginContextMenuFactories() != null) {
				Controller.getInstance().addPluginContextMenuFactories(pluginCallbacks.getPluginContextMenuFactories());
			}
			if(pluginCallbacks.getPluginTabs() != null) {
				Controller.getInstance().addPluginTabs(pluginCallbacks.getPluginTabs());
			}

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public void unloadAllPlugins() {
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
