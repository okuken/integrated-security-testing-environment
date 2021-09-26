package okuken.iste.dto;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import okuken.iste.annotations.Persistent;
import okuken.iste.plugin.PluginLoadInfo;

/**
 * [CAUTION] export/import as JSON
 */
public class UserOptionsDto {

	@Persistent(key = "dbFilePath", environmentDependent = true)
	private String dbFilePath;

	@Persistent(key = "darkTheme")
	private boolean darkTheme;

	@Persistent(key = "useKeyboardShortcutQ")
	private boolean useKeyboardShortcutQ;

	@Persistent(key = "useKeyboardShortcutWithClick")
	private boolean useKeyboardShortcutWithClick;


	@Persistent(key = "lastSelectedProjectName", environmentDependent = true)
	private String lastSelectedProjectName;

	@Persistent(key = "plugins", environmentDependent = true)
	private List<PluginLoadInfo> plugins;

	@Persistent(key = "messageMemoTemplate")
	private String messageMemoTemplate;

	@Persistent(key = "projectMemoTemplates")
	private List<String> projectMemoTemplates;

	@Persistent(key = "copyTemplates")
	private LinkedHashMap<String, String> copyTemplates;

	@Persistent(key = "copyTemplateMnemonics")
	private Map<String, String> copyTemplateMnemonics;


	public String getDbFilePath() {
		return dbFilePath;
	}
	public void setDbFilePath(String dbFilePath) {
		this.dbFilePath = dbFilePath;
	}
	public boolean isDarkTheme() {
		return darkTheme;
	}
	public void setDarkTheme(boolean darkTheme) {
		this.darkTheme = darkTheme;
	}
	public boolean isUseKeyboardShortcutQ() {
		return useKeyboardShortcutQ;
	}
	public void setUseKeyboardShortcutQ(boolean useKeyboardShortcutQ) {
		this.useKeyboardShortcutQ = useKeyboardShortcutQ;
	}
	public boolean isUseKeyboardShortcutWithClick() {
		return useKeyboardShortcutWithClick;
	}
	public void setUseKeyboardShortcutWithClick(boolean useKeyboardShortcutWithClick) {
		this.useKeyboardShortcutWithClick = useKeyboardShortcutWithClick;
	}
	public String getLastSelectedProjectName() {
		return lastSelectedProjectName;
	}
	public void setLastSelectedProjectName(String lastSelectedProjectName) {
		this.lastSelectedProjectName = lastSelectedProjectName;
	}
	public List<PluginLoadInfo> getPlugins() {
		return plugins;
	}
	public void setPlugins(List<PluginLoadInfo> plugins) {
		this.plugins = plugins;
	}
	public String getMessageMemoTemplate() {
		return messageMemoTemplate;
	}
	public void setMessageMemoTemplate(String messageMemoTemplate) {
		this.messageMemoTemplate = messageMemoTemplate;
	}
	public List<String> getProjectMemoTemplates() {
		return projectMemoTemplates;
	}
	public void setProjectMemoTemplates(List<String> projectMemoTemplates) {
		this.projectMemoTemplates = projectMemoTemplates;
	}
	public LinkedHashMap<String, String> getCopyTemplates() {
		return copyTemplates;
	}
	public void setCopyTemplates(LinkedHashMap<String, String> copyTemplates) {
		this.copyTemplates = copyTemplates;
	}
	public Map<String, String> getCopyTemplateMnemonics() {
		return copyTemplateMnemonics;
	}
	public void setCopyTemplateMnemonics(Map<String, String> copyTemplateMnemonics) {
		this.copyTemplateMnemonics = copyTemplateMnemonics;
	}
}
