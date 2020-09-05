package okuken.iste.logic;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import com.google.gson.Gson;

import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.ProcessOptionsDto;
import okuken.iste.dto.ProjectDto;
import okuken.iste.dto.ProjectOptionsDto;
import okuken.iste.dto.UserOptionsDto;
import okuken.iste.plugin.PluginLoadInfo;
import okuken.iste.util.BurpUtil;

public class ConfigLogic {

	private static final ConfigLogic instance = new ConfigLogic();

	private static final String CONFIG_KEY_USER_NAME = "userName";
	private static final String CONFIG_KEY_DB_FILE_PATH = "dbFilePath";
	private static final String CONFIG_KEY_LAST_SELECTED_PROJECT_NAME = "lastSelectedProjectName";
	private static final String CONFIG_KEY_PLUGINS = "plugins";

	//cache
	private UserOptionsDto configDto;
	private ProjectOptionsDto projectOptionsDto;
	private ProcessOptionsDto processOptionsDto = new ProcessOptionsDto();

	private ConfigLogic() {}
	public static ConfigLogic getInstance() {
		return instance;
	}

	public UserOptionsDto getUserOptions() {
		if(configDto == null) {
			//TODO: synchronize
			configDto = loadUserOptions();
		}
		return configDto;
	}
	private UserOptionsDto loadUserOptions() {
		UserOptionsDto ret = new UserOptionsDto();
		ret.setUserName(Optional.ofNullable(BurpUtil.getCallbacks().loadExtensionSetting(CONFIG_KEY_USER_NAME))
				.orElse(System.getProperty("user.name")));
		ret.setDbFilePath(BurpUtil.getCallbacks().loadExtensionSetting(CONFIG_KEY_DB_FILE_PATH));
		ret.setLastSelectedProjectName(BurpUtil.getCallbacks().loadExtensionSetting(CONFIG_KEY_LAST_SELECTED_PROJECT_NAME));

		PluginLoadInfo[] pluginLoadInfos = loadUserOptionJson(CONFIG_KEY_PLUGINS, PluginLoadInfo[].class);
		if(pluginLoadInfos != null) {
			ret.setPlugins(Arrays.asList(pluginLoadInfos));
		}

		return ret;
	}
	@SuppressWarnings("unchecked")
	private <T> T loadUserOptionJson(String configKey, Class<?> clazz) {
		var configVal = BurpUtil.getCallbacks().loadExtensionSetting(configKey);
		if(configVal == null) {
			return null;
		}
		return (T)new Gson().fromJson(configVal, clazz);
	}

	public void saveUserName(String userName) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_USER_NAME, userName);
		getUserOptions().setUserName(userName);
	}

	public String getDefaultDbFilePath() {
		return new File(System.getProperty("user.home"), "iste.db").getAbsolutePath();
	}
	public void saveDbFilePath(String dbFilePath) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_DB_FILE_PATH, dbFilePath);
		getUserOptions().setDbFilePath(dbFilePath);
	}

	public void saveLastSelectedProjectName(String projectName) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_LAST_SELECTED_PROJECT_NAME, projectName);
		getUserOptions().setLastSelectedProjectName(projectName);
	}

	public void savePlugins(List<PluginLoadInfo> pluginLoadInfos) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_PLUGINS, new Gson().toJson(pluginLoadInfos));
		getUserOptions().setPlugins(pluginLoadInfos);
	}


	public ProjectOptionsDto getProjectOptionsDto() {
		if(projectOptionsDto == null) {
			//TODO: synchronize
			projectOptionsDto = loadProjectOptions();
		}
		return projectOptionsDto;
	}
	private ProjectOptionsDto loadProjectOptions() {
		var ret = new ProjectOptionsDto();
		ret.setAuthConfigDto(AuthLogic.getInstance().loadAuthConfig());
		return ret;
	}

	public void resetProjectOptionsDto() {
		projectOptionsDto = null;
	}

	public AuthConfigDto getAuthConfig() {
		return getProjectOptionsDto().getAuthConfigDto();
	}

	public void setAuthConfig(AuthConfigDto authConfigDto) {
		getProjectOptionsDto().setAuthConfigDto(authConfigDto);
	}


	public ProcessOptionsDto getProcessOptions() {
		return processOptionsDto;
	}
	public Integer getProjectId() {
		return getProcessOptions().getProjectDto().getId();
	}

	public void setProject(ProjectDto projectDto) {
		this.processOptionsDto.setProjectDto(projectDto);
	}

}
