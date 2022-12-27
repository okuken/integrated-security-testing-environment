package okuken.iste;

import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;

import com.google.common.base.Strings;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import okuken.iste.client.BurpApiClient;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.KeyStrokeManager;
import okuken.iste.view.SuiteTab;

public class IntegratedSecurityTestingEnvironment implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
		BurpApiClient.init(burpExtenderCallbacks);
		initImpl();
	}

	private void initImpl() {
		BurpApiClient.i().setExtensionName(Captions.EXTENSION_NAME_FULL);

		BurpApiClient.i().registerContextMenuFactory(ContextMenuFactory.create());

		BurpApiClient.i().registerExtensionStateListener(new ExtensionStateListener());

		setupDatabase();
		ProjectLogic.getInstance().selectProject();

		SwingUtilities.invokeLater(() -> {
			SuiteTab suiteTab = new SuiteTab();

			Controller controller = Controller.getInstance();
			controller.setSuiteTab(suiteTab);
			controller.loadDatabase();
			controller.loadPlugins();

			BurpApiClient.i().addSuiteTab(suiteTab);

			UiUtil.invokeLater(() -> {
				controller.initSizeRatioOfParts();

				if(ConfigLogic.getInstance().getUserOptions().isUseKeyboardShortcutQ()) {
					KeyStrokeManager.getInstance().setupKeyStroke();
				}
			}, 3);
		});
	}

	private void setupDatabase() {
		ConfigLogic configLogic = ConfigLogic.getInstance();
		if(judgeNeedChooseDbFilePath(configLogic.getUserOptions().getDbFilePath())) {
			JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_DB_FILE, configLogic.getDefaultDbFile());
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
	private boolean judgeNeedChooseDbFilePath(String dbFilePath) {
		return Strings.isNullOrEmpty(dbFilePath) ||
				!new File(dbFilePath).exists();
	}

}