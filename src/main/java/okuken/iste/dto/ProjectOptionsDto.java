package okuken.iste.dto;

import java.util.Map;

public class ProjectOptionsDto {

	private AuthConfigDto authConfigDto;

	private Map<String, Map<String, PluginProjectOptionDto>> pluginOptions;

	public AuthConfigDto getAuthConfigDto() {
		return authConfigDto;
	}
	public void setAuthConfigDto(AuthConfigDto authConfigDto) {
		this.authConfigDto = authConfigDto;
	}
	public Map<String, Map<String, PluginProjectOptionDto>> getPluginOptions() {
		return pluginOptions;
	}
	public void setPluginOptions(Map<String, Map<String, PluginProjectOptionDto>> pluginOptions) {
		this.pluginOptions = pluginOptions;
	}

}
