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
import java.util.Comparator;
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

import okuken.iste.client.BurpApiClient;
import okuken.iste.consts.Colors;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpServiceDto;
import okuken.iste.view.message.editor.HttpMessageEditor;

public class BurpUtil {

	public static boolean isInScope(byte[] request, HttpServiceDto httpService) {
		return isInScope(BurpApiClient.i().analyzeRequest(new HttpRequestResponseDto(request, null, httpService)).getUrl());
	}
	public static boolean isInScope(URL url) {
		return BurpApiClient.i().isInScope(url);
	}

	public static void printEventLog(String msg) {
		System.err.println(msg);
		BurpApiClient.i().issueAlert(msg);
	}

	public static void printStderr(Exception e) {
		e.printStackTrace();
		e.printStackTrace(new PrintWriter(BurpApiClient.i().getStderr(), true));
	}
	public static void printStderr(String msg) {
		var errMsg = "[ISTE]ERROR: " + msg;
		System.err.println(errMsg);
		BurpApiClient.i().printError(errMsg);
	}
	public static void printStdout(String msg) {
		var infoMsg = "[ISTE]INFO: " + msg;
		System.out.println(infoMsg);
		getStdoutPrintStream().println(infoMsg);
	}

	public static PrintStream getStdoutPrintStream() {
		return new PrintStream(BurpApiClient.i().getStdout());
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
		BurpApiClient.i().customizeUiComponent(dummyUiComponent);
		return dummyUiComponent.getForeground();
	}

	public static String getBurpSuiteVersion() {
		return Arrays.stream(BurpApiClient.i().getBurpVersion()).collect(Collectors.joining(" "));
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
	private static final int PROXY_HTTP_HISTORY_TABLE_CANDIDATE_MIN_COLUMN_COUNT = 5;
	private static final int PROXY_HTTP_HISTORY_TABLE_CONFIDENCE_THRESHOLD = 10;

	public static void extractBurpSuiteProxyHttpHistoryTable() {
		if(isBurpSuiteProxyHttpHistoryTableExtracted()) {
			return;
		}

		var candidates = new ArrayList<JTable>();
		extractBurpSuiteProxyHttpHistoryTableImpl(getBurpSuiteJFrame(), candidates);
		if(candidates.isEmpty()) {
			printStderr("extractBurpSuiteProxyHttpHistoryTable failed(no candidate JTable found). Burp version: " + getBurpSuiteVersion());
			return;
		}

		var best = candidates.stream()
				.max(Comparator.comparingInt(BurpUtil::scoreAsProxyHttpHistoryTableCandidate))
				.get();
		if(scoreAsProxyHttpHistoryTableCandidate(best) < PROXY_HTTP_HISTORY_TABLE_CONFIDENCE_THRESHOLD) {
			printStderr("extractBurpSuiteProxyHttpHistoryTable failed(no confident candidate). Burp version: " + getBurpSuiteVersion()
					+ ". Candidates: " + candidates.stream().map(BurpUtil::describeProxyHttpHistoryTableCandidate).collect(Collectors.joining(" | ")));
			return;
		}

		burpSuiteProxyHttpHistoryTable = best;
		printStdout("extractBurpSuiteProxyHttpHistoryTable succeeded: " + describeProxyHttpHistoryTableCandidate(best));
	}
	// Burp doesn't expose the HTTP history table via any public API, so this walks Burp's own (undocumented,
	// version-dependent) Swing component tree. Rather than relying on a single hardcoded internal component
	// name(which Burp is free to rename/obfuscate between versions), every JTable with a plausible column
	// count is collected here and the most likely one is picked by scoreAsProxyHttpHistoryTableCandidate.
	private static void extractBurpSuiteProxyHttpHistoryTableImpl(Component component, List<JTable> ret) {
		if(component instanceof JTable) {
			var table = (JTable)component;
			if(table.getColumnCount() > PROXY_HTTP_HISTORY_TABLE_CANDIDATE_MIN_COLUMN_COUNT) {
				ret.add(table);
			}
		}
		if(component instanceof Container) {
			for(var childComponent: ((Container)component).getComponents()) {
				extractBurpSuiteProxyHttpHistoryTableImpl(childComponent, ret); //recursive
			}
		}
	}
	private static int scoreAsProxyHttpHistoryTableCandidate(JTable table) {
		var score = 0;

		var tabTitles = getAncestorTabTitles(table);
		if(tabTitles.stream().anyMatch(title -> StringUtils.containsIgnoreCase(title, "proxy"))
				&& tabTitles.stream().anyMatch(title -> StringUtils.containsIgnoreCase(title, "history"))) {
			score += 100; // structural: nested under Proxy > *history* tab. Tab titles are user-visible text, so unlike internal component names, they can't be silently renamed without the user noticing.
		}

		if("#".equals(String.valueOf(getColumnHeaderValue(table, 0)))) {
			score += 10; // "#" row-number column, used elsewhere in this codebase(extractProxyHttpHistoryNumber) as column 0 of the history table.
		}

		if(table.getColumnCount() > 15) {
			score += 5; // the original(pre-2023) heuristic; kept as a weak signal since Burp's history table has only grown more columns over time.
		}

		if(StringUtils.containsIgnoreCase(StringUtils.defaultString(table.getName()), "history")
				|| StringUtils.containsIgnoreCase(StringUtils.defaultString(table.getName()), "proxy")) {
			score += 3;
		}

		return score;
	}
	private static List<String> getAncestorTabTitles(Component component) {
		var titles = new ArrayList<String>();
		var child = component;
		var parent = component.getParent();
		while(parent != null) {
			if(parent instanceof JTabbedPane) {
				var tabbedPane = (JTabbedPane)parent;
				var index = tabbedPane.indexOfComponent(child);
				if(index >= 0) {
					titles.add(StringUtils.defaultString(tabbedPane.getTitleAt(index)));
				}
			}
			child = parent;
			parent = parent.getParent();
		}
		return titles;
	}
	private static Object getColumnHeaderValue(JTable table, int columnIndex) {
		try {
			return table.getColumnModel().getColumn(columnIndex).getHeaderValue();
		} catch (Exception e) {
			return null;
		}
	}
	private static String describeProxyHttpHistoryTableCandidate(JTable table) {
		return String.format("[name=%s, columnCount=%d, column0Header=%s, score=%d, tabTitles=%s]",
				table.getName(), table.getColumnCount(), getColumnHeaderValue(table, 0),
				scoreAsProxyHttpHistoryTableCandidate(table), getAncestorTabTitles(table));
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
			professionalEdition = BurpApiClient.i().getBurpVersion()[0].contains("Professional");
		}
		return professionalEdition;
	}

}