package okuken.iste.util;

import java.awt.Frame;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.ITab;
import okuken.iste.consts.Colors;
import okuken.iste.dto.burp.HttpRequestResponseMock;

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

	public static boolean isInScope(byte[] request, IHttpService httpService) {
		return isInScope(getHelpers().analyzeRequest(new HttpRequestResponseMock(request, null, httpService)).getUrl());
	}
	public static boolean isInScope(URL url) {
		return burpExtenderCallbacks.isInScope(url);
	}

	public static void printEventLog(String msg) {
		burpExtenderCallbacks.issueAlert(msg);
	}

	public static void printStderr(Exception e) {
		e.printStackTrace(new PrintWriter(burpExtenderCallbacks.getStderr(), true));
	}

	public static PrintStream getStdoutPrintStream() {
		return new PrintStream(burpExtenderCallbacks.getStdout());
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

	public static JFrame getBurpSuiteJFrame() {
		return (JFrame) Arrays.stream(Frame.getFrames())
				.filter(frame -> frame.isVisible() && frame.getTitle().startsWith(("Burp Suite")))
				.collect(Collectors.toList()).get(0);
	}

	private static final Pattern burpSuiteProjectNamePattern = Pattern.compile("^[^-]+ - (.+) - licensed to .+$");
	public static String getBurpSuiteProjectName() {
		var matcher = burpSuiteProjectNamePattern.matcher(getBurpSuiteJFrame().getTitle());
		if(!matcher.find()) {
			return null;
		}

		var burpSuiteProjectName = matcher.group(1);
		if(burpSuiteProjectName.equals("Temporary Project")) {
			return null;
		}
		return burpSuiteProjectName;
	}

	private static Boolean professionalEdition;
	public static boolean isProfessionalEdition() {
		if(professionalEdition == null) {
			professionalEdition = burpExtenderCallbacks.getBurpVersion()[0].contains("Professional");
		}
		return professionalEdition;
	}

}