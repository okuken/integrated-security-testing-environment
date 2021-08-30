package okuken.iste.dto;

import java.util.List;
import java.util.Map;

import okuken.iste.plugin.PluginLoadInfo;

public class UserOptionsDto {

	private String userName;
	private String dbFilePath;
	private boolean darkTheme;
	private String lastSelectedProjectName;
	private List<PluginLoadInfo> plugins;
	private String messageMemoTemplate;
	private List<String> projectMemoTemplates;
	private Map<String, String> copyTemplates;
	private Map<String, String> copyTemplateMnemonics;

	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
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
	public Map<String, String> getCopyTemplates() {
		return copyTemplates;
	}
	public void setCopyTemplates(Map<String, String> copyTemplates) {
		this.copyTemplates = copyTemplates;
	}
	public Map<String, String> getCopyTemplateMnemonics() {
		return copyTemplateMnemonics;
	}
	public void setCopyTemplateMnemonics(Map<String, String> copyTemplateMnemonics) {
		this.copyTemplateMnemonics = copyTemplateMnemonics;
	}
}
