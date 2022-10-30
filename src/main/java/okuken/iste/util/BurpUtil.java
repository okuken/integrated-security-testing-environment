package okuken.iste.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Frame;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.TableModel;
import javax.swing.text.JTextComponent;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.Lists;

import okuken.iste.consts.Colors;
import okuken.iste.dto.HttpMessageEditor;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpServiceDto;

public class BurpUtil {

	public static boolean isInScope(byte[] request, HttpServiceDto httpService) {
		return isInScope(BurpApiUtil.i().analyzeRequest(new HttpRequestResponseDto(request, null, httpService)).getUrl());
	}
	public static boolean isInScope(URL url) {
		return BurpApiUtil.i().isInScope(url);
	}

	public static void printEventLog(String msg) {
		System.err.println(msg);
		BurpApiUtil.i().issueAlert(msg);
	}

	public static void printStderr(Exception e) {
		e.printStackTrace();
		e.printStackTrace(new PrintWriter(BurpApiUtil.i().getStderr(), true));
	}
	public static void printStderr(String msg) {
		var errMsg = "[ISTE]ERROR: " + msg;
		System.err.println(errMsg);
		BurpApiUtil.i().printError(errMsg);
	}

	public static PrintStream getStdoutPrintStream() {
		return new PrintStream(BurpApiUtil.i().getStdout());
	}

	public static void highlightTab(Component suiteTabUiComponent) {
		JTabbedPane parentTabbedPane = (JTabbedPane)suiteTabUiComponent.getParent();
		parentTabbedPane.setBackgroundAt(indexOf(suiteTabUiComponent, parentTabbedPane), Colors.CHARACTER_HIGHLIGHT);
		new Timer().schedule(new TimerTask() {
			@Override
			public void run() {
				parentTabbedPane.setBackgroundAt(indexOf(suiteTabUiComponent, parentTabbedPane), getDefaultForegroundColor());
			}
		}, 5000);
	}
	private static int indexOf(Component suiteTabUiComponent, JTabbedPane tabbedPane) {
		for (int i = 0; i < tabbedPane.getTabCount(); i++) {
			if (tabbedPane.getComponentAt(i) == suiteTabUiComponent) {
				return i;
			}
		}
		throw new IllegalStateException();
	}

	public static Color getDefaultForegroundColor() {
		var dummyUiComponent = new JLabel("dummy");
		BurpApiUtil.i().customizeUiComponent(dummyUiComponent);
		return dummyUiComponent.getForeground();
	}

	public static String getBurpSuiteVersion() {
		return Arrays.stream(BurpApiUtil.i().getBurpVersion()).collect(Collectors.joining(" "));
	}

	public static JFrame getBurpSuiteJFrame() {
		return (JFrame) Arrays.stream(Frame.getFrames())
				.filter(frame -> frame.isVisible() && frame.getTitle().startsWith(("Burp Suite")))
				.collect(Collectors.toList()).get(0);
	}

	public static String getBurpSuiteProjectName() {
		return extractBurpSuiteProjectNameFromFrameTitle(getBurpSuiteJFrame().getTitle());
	}

	private static final Pattern burpSuiteProjectNamePattern = Pattern.compile("^.+? - (.+) - licensed to .+$");
	public static String extractBurpSuiteProjectNameFromFrameTitle(String frameTitle) {
		var matcher = burpSuiteProjectNamePattern.matcher(frameTitle);
		if(!matcher.find()) {
			return null;
		}

		var burpSuiteProjectName = matcher.group(1);
		if(burpSuiteProjectName.equals("Temporary Project")) {
			return null;
		}
		return burpSuiteProjectName;
	}

	public static final Optional<Boolean> isDarkTheme() {
		var lookAndFeelName = UiUtil.getLookAndFeelName();
		if(isDarkThemeImpl(lookAndFeelName)) {
			return Optional.of(Boolean.TRUE);
		}
		if(isLightThemeImpl(lookAndFeelName)) {
			return Optional.of(Boolean.FALSE);
		}
		return Optional.empty();
	}
	private static final boolean isDarkThemeImpl(String lookAndFeelName) {
		return StringUtils.contains(StringUtils.upperCase(lookAndFeelName), "DARK");
	}
	private static final boolean isLightThemeImpl(String lookAndFeelName) {
		return StringUtils.contains(StringUtils.upperCase(lookAndFeelName), "LIGHT");
	}

	private static JTable burpSuiteProxyHttpHistoryTable;
	public static boolean isBurpSuiteProxyHttpHistoryTableExtracted() {
		return burpSuiteProxyHttpHistoryTable != null;
	}
	public static JTable getBurpSuiteProxyHttpHistoryTable() {
		if(!isBurpSuiteProxyHttpHistoryTableExtracted()) {
			extractBurpSuiteProxyHttpHistoryTable();
		}
		return burpSuiteProxyHttpHistoryTable;
	}
	public static void extractBurpSuiteProxyHttpHistoryTable() {
		if(isBurpSuiteProxyHttpHistoryTableExtracted()) {
			return;
		}

		var ret = new ArrayList<JTable>();
		extractBurpSuiteProxyHttpHistoryTableImpl(getBurpSuiteJFrame(), ret);
		if(ret.isEmpty()) {
			printStderr("extractBurpSuiteProxyHttpHistoryTable failed. Burp version: " + getBurpSuiteVersion());
			return;
		}
		burpSuiteProxyHttpHistoryTable = ret.get(0);
	}
	private static void extractBurpSuiteProxyHttpHistoryTableImpl(Component component, List<JTable> ret) {
		if(!ret.isEmpty()) {
			return;
		}
		if(component instanceof JTable) {
			var table = (JTable)component;
			if("proxyHistoryTable".equals(table.getName()) && table.getColumnCount() > 15) {
				ret.add(table);
				return;
			}
		}
		if(component instanceof Container) {
			for(var childComponent: ((Container)component).getComponents()) {
				extractBurpSuiteProxyHttpHistoryTableImpl(childComponent, ret); //recursive
			}
			return;
		}
	}

	public static Integer extractProxyHttpHistoryNumber(TableModel burpSuiteProxyHttpHistoryTableModel, int tableModelRowIndex) {
		return (Integer)burpSuiteProxyHttpHistoryTableModel.getValueAt(tableModelRowIndex, 0); // value of "#" column
	}


	public static JTextComponent extractMessageEditorTextComponent(HttpMessageEditor messageEditor) {
		List<JTextComponent> ret = Lists.newArrayList();
		extractMessageEditorTextComponentImpl(messageEditor.getComponent(), ret);
		if(ret.isEmpty()) {
			printStderr("extractMessageEditorTextComponent failed.");
			return null;
		}
		return ret.get(0);
	}
	private static void extractMessageEditorTextComponentImpl(Component component, List<JTextComponent> ret) {
		if(!ret.isEmpty()) {
			return;
		}
		if(component instanceof JTextArea) {
			ret.add((JTextArea)component);
			return;
		}
		if(component instanceof Container) {
			for(var childComponent: ((Container)component).getComponents()) {
				extractMessageEditorTextComponentImpl(childComponent, ret); //recursive
			}
		}
	}


	private static Boolean professionalEdition;
	public static boolean isProfessionalEdition() {
		if(professionalEdition == null) {
			professionalEdition = BurpApiUtil.i().getBurpVersion()[0].contains("Professional");
		}
		return professionalEdition;
	}

}