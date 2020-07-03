package okuken.iste.logic;

import java.io.File;
import java.util.Optional;

import okuken.iste.dto.ProcessOptionsDto;
import okuken.iste.dto.ProjectDto;
import okuken.iste.dto.UserOptionsDto;
import okuken.iste.util.BurpUtil;

public class ConfigLogic {

	private static final ConfigLogic instance = new ConfigLogic();

	private static final String CONFIG_KEY_USER_NAME = "userName";
	private static final String CONFIG_KEY_DB_FILE_PATH = "dbFilePath";

	private UserOptionsDto configDto;
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
		return ret;
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
