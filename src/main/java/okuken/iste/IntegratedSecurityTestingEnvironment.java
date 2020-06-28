package okuken.iste;

import java.io.File;

import javax.swing.SwingUtilities;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dao.DatabaseManager;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.SuiteTab;

public class IntegratedSecurityTestingEnvironment implements IBurpExtender, IExtensionStateListener {
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
		BurpUtil.init(burpExtenderCallbacks);

		burpExtenderCallbacks.setExtensionName(Captions.EXTENSION_NAME);

		burpExtenderCallbacks.registerContextMenuFactory(ContextMenuFactory.create());

		burpExtenderCallbacks.registerExtensionStateListener(this);

		DatabaseManager.getInstance().setupDatabase(
				new File(System.getProperty("user.home"), "iste.db").getAbsolutePath().replaceAll("\\\\", "/")); //TODO:option

		SwingUtilities.invokeLater(() -> {
			SuiteTab suiteTab = new SuiteTab();
			Controller.getInstance().setSuiteTab(suiteTab);
			burpExtenderCallbacks.addSuiteTab(suiteTab);
		});
	}

	@Override
	public void extensionUnloaded() {
		DatabaseManager.getInstance().unloadDatabase();
	}

}