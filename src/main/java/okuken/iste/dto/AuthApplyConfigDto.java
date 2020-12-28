package okuken.iste.dto;

import okuken.iste.enums.RequestParameterType;

public class AuthApplyConfigDto {

	private Integer id;
	private Integer authConfigId;

	private RequestParameterType paramType;
	private String paramName;
	private String varName;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public Integer getAuthConfigId() {
		return authConfigId;
	}
	public void setAuthConfigId(Integer authConfigId) {
		this.authConfigId = authConfigId;
	}
	public RequestParameterType getParamType() {
		return paramType;
	}
	public void setParamType(RequestParameterType paramType) {
		this.paramType = paramType;
	}
	public String getParamName() {
		return paramName;
	}
	public void setParamName(String paramName) {
		this.paramName = paramName;
	}
	public String getVarName() {
		return varName;
	}
	public void setVarName(String varName) {
		this.varName = varName;
	}

}
