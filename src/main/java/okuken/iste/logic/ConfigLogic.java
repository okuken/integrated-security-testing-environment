package okuken.iste.logic;

import java.io.File;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.google.common.collect.Maps;
import com.google.gson.Gson;

import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.PluginProjectOptionDto;
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
	private static final String CONFIG_KEY_MESSAGE_MEMO_TEMPLATE = "messageMemoTemplate";
	private static final String CONFIG_KEY_PROJECT_MEMO_TEMPLATES = "projectMemoTemplates";
	private static final String CONFIG_KEY_COPY_TEMPLATES = "copyTemplates";

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

		ret.setMessageMemoTemplate(BurpUtil.getCallbacks().loadExtensionSetting(CONFIG_KEY_MESSAGE_MEMO_TEMPLATE));
		ret.setProjectMemoTemplates(loadUserOptionJson(CONFIG_KEY_PROJECT_MEMO_TEMPLATES, List.class));
		ret.setCopyTemplates(loadUserOptionJson(CONFIG_KEY_COPY_TEMPLATES, LinkedHashMap.class));

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

	public File getDefaultDbFile() {
		return new File(System.getProperty("user.home"), "iste.db");
	}
	public String getDefaultDbFilePath() {
		return getDefaultDbFile().getAbsolutePath();
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

	public void saveMessageMemoTemplate(String messageMemoTemplate) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_MESSAGE_MEMO_TEMPLATE, messageMemoTemplate);
		getUserOptions().setMessageMemoTemplate(messageMemoTemplate);
	}

	public void saveProjectMemoTemplates(List<String> projectMemoTemplates) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_PROJECT_MEMO_TEMPLATES, new Gson().toJson(projectMemoTemplates));
		getUserOptions().setProjectMemoTemplates(projectMemoTemplates);
	}

	public void saveCopyTemplates(Map<String, String> copyTemplates) {
		BurpUtil.getCallbacks().saveExtensionSetting(CONFIG_KEY_COPY_TEMPLATES, new Gson().toJson(copyTemplates));
		getUserOptions().setCopyTemplates(copyTemplates);
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
		ret.setAuthConfigDto(loadOrInitAuthConfig());
		ret.setPluginOptions(ProjectOptionLogic.getInstance().loadPluginProjectOptions(getProjectId()));
		return ret;
	}
	private AuthConfigDto loadOrInitAuthConfig() {
		var authConfigDto = AuthLogic.getInstance().loadAuthConfig();
		if(authConfigDto == null) {
			return AuthLogic.getInstance().initAuthConfig();
		}
		return authConfigDto;
	}

	public void resetProjectOptionsDto() {
		projectOptionsDto = null;
	}

	public AuthConfigDto getAuthConfig() {
		return getProjectOptionsDto().getAuthConfigDto();
	}
	public boolean isAuthConfigReady() {
		var authConfig = getAuthConfig();
		return authConfig != null && authConfig.isReady();
	}

	public void setAuthConfig(AuthConfigDto authConfigDto) {
		getProjectOptionsDto().setAuthConfigDto(authConfigDto);
	}

	public String getPluginProjectOption(String pluginName, String key) {
		var specificPluginProjectOptions = getSpecificPluginProjectOptions(pluginName);
		if(specificPluginProjectOptions == null || !specificPluginProjectOptions.containsKey(key)) {
			return null;
		}
		return specificPluginProjectOptions.get(key).getVal();
	}
	private Map<String, PluginProjectOptionDto> getSpecificPluginProjectOptions(String pluginName) {
		if(!getProjectOptionsDto().getPluginOptions().containsKey(pluginName)) {
			return null;
		}
		return getProjectOptionsDto().getPluginOptions().get(pluginName);
	}

	public void savePluginProjectOption(String pluginName, String key, String value) {
		var specificPluginProjectOptions = getSpecificPluginProjectOptions(pluginName);

		if(specificPluginProjectOptions == null || !specificPluginProjectOptions.containsKey(key)) {
			var dto = new PluginProjectOptionDto(key, value);
			ProjectOptionLogic.getInstance().savePluginProjectOption(getProjectId(), pluginName, dto);

			if(specificPluginProjectOptions == null) {
				Map<String, PluginProjectOptionDto> newSpecificPluginProjectOptions = Maps.newHashMap();
				newSpecificPluginProjectOptions.put(key, dto);
				getProjectOptionsDto().getPluginOptions().put(pluginName, newSpecificPluginProjectOptions);
				return;
			}

			specificPluginProjectOptions.put(key, dto);
			return;
		}

		var dto = specificPluginProjectOptions.get(key);
		dto.setVal(value);
		ProjectOptionLogic.getInstance().updatePluginProjectOption(dto);
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
