package okuken.iste;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;

import com.google.common.base.Strings;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.SuiteTab;

public class IntegratedSecurityTestingEnvironment implements IBurpExtender, IExtensionStateListener {
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
		BurpUtil.init(burpExtenderCallbacks);
		try {
			burpExtenderCallbacks.setExtensionName(Captions.EXTENSION_NAME);

			burpExtenderCallbacks.registerContextMenuFactory(ContextMenuFactory.create());

			burpExtenderCallbacks.registerExtensionStateListener(this);

			setupDatabase();
			ProjectLogic.getInstance().selectProject();

			SwingUtilities.invokeLater(() -> {
				SuiteTab suiteTab = new SuiteTab();

				Controller controller = Controller.getInstance();
				controller.setSuiteTab(suiteTab);
				controller.loadDatabase();

				burpExtenderCallbacks.addSuiteTab(suiteTab);
			});

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw new RuntimeException(e);
		}
	}

	private void setupDatabase() {
		ConfigLogic configLogic = ConfigLogic.getInstance();
		if(Strings.isNullOrEmpty(configLogic.getUserOptions().getDbFilePath())) {
			JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_DB_FILE);
			switch (fileChooser.showSaveDialog(BurpUtil.getBurpSuiteJFrame())) {
				case JFileChooser.APPROVE_OPTION:
					configLogic.saveDbFilePath(fileChooser.getSelectedFile().getAbsolutePath());
					break;
				default:
					configLogic.saveDbFilePath(configLogic.getDefaultDbFilePath());
					break;
			};
		}

		DatabaseManager.getInstance().setupDatabase(configLogic.getUserOptions().getDbFilePath());
	}

	@Override
	public void extensionUnloaded() {
		DatabaseManager.getInstance().unloadDatabase();
	}

}