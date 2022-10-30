package okuken.iste;

import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;

import com.google.common.base.Strings;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.misc.ExtensionUnloadHandler;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.logic.RepeaterLogic;
import okuken.iste.plugin.PluginManager;
import okuken.iste.util.BurpApiUtil;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;
import okuken.iste.util.ThreadUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.KeyStrokeManager;
import okuken.iste.view.SuiteTab;

public class IntegratedSecurityTestingEnvironment implements /*BurpExtension, */ExtensionUnloadHandler, IBurpExtender, IExtensionStateListener {

//	@Override
//	public void initialize(MontoyaApi api) {
//		BurpApiUtil.init(api);
//		initImpl();
//	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
		BurpApiUtil.init(burpExtenderCallbacks);
		initImpl();
	}

	private void initImpl() {
		BurpApiUtil.i().setExtensionName(Captions.EXTENSION_NAME_FULL);

		BurpApiUtil.i().registerContextMenuFactory(ContextMenuFactory.create());

		BurpApiUtil.i().registerExtensionStateListener(this);

		setupDatabase();
		ProjectLogic.getInstance().selectProject();

		SwingUtilities.invokeLater(() -> {
			SuiteTab suiteTab = new SuiteTab();

			Controller controller = Controller.getInstance();
			controller.setSuiteTab(suiteTab);
			controller.loadDatabase();
			controller.loadPlugins();

			BurpApiUtil.i().addSuiteTab(suiteTab);

			SwingUtilities.invokeLater(() -> {
				controller.initSizeRatioOfParts();

				if(ConfigLogic.getInstance().getUserOptions().isUseKeyboardShortcutQ()) {
					KeyStrokeManager.getInstance().setupKeyStroke();
				}
			});
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