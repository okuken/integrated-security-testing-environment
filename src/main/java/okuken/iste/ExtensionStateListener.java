package okuken.iste;

import burp.IExtensionStateListener;
import okuken.iste.logic.RepeaterLogic;
import okuken.iste.plugin.PluginManager;
import okuken.iste.util.ThreadUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.KeyStrokeManager;

public class ExtensionStateListener implements IExtensionStateListener {

	@Override
	public void extensionUnloaded() {
		RepeaterLogic.getInstance().shutdownExecutorService();
		ThreadUtil.shutdownExecutorService();
		PluginManager.getInstance().unloadAllPlugins();
		DatabaseManager.getInstance().unloadDatabase();
		KeyStrokeManager.getInstance().unloadKeyStroke();
		UiUtil.disposeDockoutFrames();
		UiUtil.disposePopupFrames();
	}

}
