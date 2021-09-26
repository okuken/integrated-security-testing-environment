package okuken.iste.logic;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.beanutils.BeanUtils;

import com.google.common.collect.Maps;
import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import okuken.iste.annotations.Persistent;
import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.PluginProjectOptionDto;
import okuken.iste.dto.ProcessOptionsDto;
import okuken.iste.dto.ProjectDto;
import okuken.iste.dto.ProjectOptionsDto;
import okuken.iste.dto.UserOptionsDto;
import okuken.iste.plugin.PluginLoadInfo;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;
import okuken.iste.util.ReflectionUtil;

public class ConfigLogic {

	private static final ConfigLogic instance = new ConfigLogic();

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
		Arrays.asList(UserOptionsDto.class.getDeclaredFields()).stream()
			.filter(field -> field.isAnnotationPresent(Persistent.class))
			.forEach(field -> {
				var valueStr = BurpUtil.getCallbacks().loadExtensionSetting(field.getAnnotation(Persistent.class).key());
				ReflectionUtil.setPropertyByValueStr(ret, field, valueStr);
			});
		return ret;
	}

	public File getDefaultDbFile() {
		return new File(System.getProperty("user.home"), "iste.db");
	}
	public String getDefaultDbFilePath() {
		return getDefaultDbFile().getAbsolutePath();
	}
	public void saveDbFilePath(String dbFilePath) {
		saveUserOption("dbFilePath", dbFilePath);
	}

	public void saveDarkTheme(boolean darkTheme) {
		saveUserOption("darkTheme", darkTheme);
	}
	public void saveLastSelectedProjectName(String projectName) {
		saveUserOption("lastSelectedProjectName", projectName);
	}
	public void savePlugins(List<PluginLoadInfo> pluginLoadInfos) {
		saveUserOption("plugins", pluginLoadInfos);
	}
	public void saveMessageMemoTemplate(String messageMemoTemplate) {
		saveUserOption("messageMemoTemplate", messageMemoTemplate);
	}
	public void saveProjectMemoTemplates(List<String> projectMemoTemplates) {
		saveUserOption("projectMemoTemplates", projectMemoTemplates);
	}
	public void saveCopyTemplates(Map<String, String> copyTemplates, Map<String, String> copyTemplateMnemonics) {
		saveUserOption("copyTemplates", copyTemplates);
		saveUserOption("copyTemplateMnemonics", copyTemplateMnemonics);
	}
	public void saveUseKeyboardShortcutQ(boolean useKeyboardShortcutQ) {
		saveUserOption("useKeyboardShortcutQ", useKeyboardShortcutQ);
	}
	public void saveUseKeyboardShortcutWithClick(boolean useKeyboardShortcutWithClick) {
		saveUserOption("useKeyboardShortcutWithClick", useKeyboardShortcutWithClick);
	}

	private void saveUserOption(String fieldName, String value) {
		saveUserOption(fieldName, value, value);
	}
	private void saveUserOption(String fieldName, boolean value) {
		saveUserOption(fieldName, value, Boolean.toString(value));
	}
	private void saveUserOption(String fieldName, Object value) {
		if(value == null) {
			saveUserOption(fieldName, value, null);
			return;
		}
		saveUserOption(fieldName, value, new Gson().toJson(value));
	}
	private void saveUserOption(String fieldName, Object value, String valueStr) {
		try {
			BurpUtil.getCallbacks().saveExtensionSetting(UserOptionsDto.class.getDeclaredField(fieldName).getAnnotation(Persistent.class).key(), valueStr);
			BeanUtils.setProperty(getUserOptions(), fieldName, value);
		} catch (NoSuchFieldException | SecurityException | IllegalAccessException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}

	public void exportUserOptions(File file) {
		var gson = new GsonBuilder().addSerializationExclusionStrategy(new ExclusionStrategy() {
			@Override
			public boolean shouldSkipField(FieldAttributes f) {
				var persistent = f.getAnnotation(Persistent.class);
				return persistent == null || persistent.environmentDependent();
			}
			@Override
			public boolean shouldSkipClass(Class<?> clazz) {
				return false;
			}
		}).setPrettyPrinting().create();

		var userOptionsJson = gson.toJson(getUserOptions());
		FileUtil.write(file, userOptionsJson);
	}

	public void importUserOptions(File file) {
		var userOptionsMap = new Gson().fromJson(FileUtil.read(file), Map.class);

		Arrays.asList(UserOptionsDto.class.getDeclaredFields()).stream()
			.filter(field -> field.isAnnotationPresent(Persistent.class) && !field.getAnnotation(Persistent.class).environmentDependent())
			.filter(field -> userOptionsMap.containsKey(field.getName()))
			.forEach(field -> {
				var valueStr = convertValueMapToStr(userOptionsMap.get(field.getName()));
				saveUserOption(field.getName(), ReflectionUtil.convertValueStrToObject(field, valueStr));
			});
	}
	private String convertValueMapToStr(Object valueMap) {
		if(valueMap.getClass() == String.class) {
			return (String)valueMap;
		}
		return new Gson().toJson(valueMap);
	}

	public void clearUserOptions() {
		Arrays.asList(UserOptionsDto.class.getDeclaredFields()).stream()
			.filter(field -> field.isAnnotationPresent(Persistent.class))
			.map(field -> field.getAnnotation(Persistent.class).key())
			.forEach(key -> BurpUtil.getCallbacks().saveExtensionSetting(key, null));
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
