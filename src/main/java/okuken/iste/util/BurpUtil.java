package okuken.iste.util;

import java.io.PrintWriter;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.JTabbedPane;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import okuken.iste.consts.Colors;

public class BurpUtil {

	private static IBurpExtenderCallbacks burpExtenderCallbacks;

	public static void init(IBurpExtenderCallbacks burpExtenderCallbacks) {
		BurpUtil.burpExtenderCallbacks = burpExtenderCallbacks;
	}

	public static IBurpExtenderCallbacks getCallbacks() {
		return burpExtenderCallbacks;
	}

	public static IExtensionHelpers getHelpers() {
		return getCallbacks().getHelpers();
	}

	public static void printStderr(Exception e) {
		e.printStackTrace(new PrintWriter(burpExtenderCallbacks.getStderr(), true));
	}

	public static void highlightTab(ITab suiteTab) {
		JTabbedPane parentTabbedPane = (JTabbedPane)suiteTab.getUiComponent().getParent();
		parentTabbedPane.setBackgroundAt(indexOf(suiteTab, parentTabbedPane), Colors.CHARACTER_HIGHLIGHT);
		new Timer().schedule(new TimerTask() {
			@Override
			public void run() {
				parentTabbedPane.setBackgroundAt(indexOf(suiteTab, parentTabbedPane), Colors.CHARACTER_NORMAL);
			}
		}, 5000);
	}
	private static int indexOf(ITab suiteTab, JTabbedPane tabbedPane) {
		for (int i = 0; i < tabbedPane.getTabCount(); i++) {
			if (tabbedPane.getComponentAt(i) == suiteTab.getUiComponent()) {
				return i;
			}
		}
		throw new IllegalStateException();
	}

}