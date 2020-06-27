package okuken.iste;

import javax.swing.SwingUtilities;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.SuiteTab;

public class IntegratedSecurityTestingEnvironment implements IBurpExtender {
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
		BurpUtil.init(burpExtenderCallbacks);

		burpExtenderCallbacks.setExtensionName(Captions.EXTENSION_NAME);

		burpExtenderCallbacks.registerContextMenuFactory(ContextMenuFactory.create());

		SwingUtilities.invokeLater(() -> {
			SuiteTab suiteTab = new SuiteTab();
			Controller.getInstance().setSuiteTab(suiteTab);
			burpExtenderCallbacks.addSuiteTab(suiteTab);
		});
	}
}