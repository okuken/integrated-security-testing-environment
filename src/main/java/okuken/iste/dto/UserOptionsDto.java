package okuken.iste.dto;

import java.util.List;

import okuken.iste.plugin.PluginLoadInfo;

public class UserOptionsDto {

	private String userName;
	private String dbFilePath;
	private String lastSelectedProjectName;
	private List<PluginLoadInfo> plugins;
	private String messageMemoTemplate;
	private List<String> projectMemoTemplates;

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

}
