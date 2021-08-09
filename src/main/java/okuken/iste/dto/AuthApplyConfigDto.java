package okuken.iste.dto;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.enums.EncodeType;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;

public class AuthApplyConfigDto {

	private Integer id;
	private Integer authConfigId;

	private RequestParameterType paramType;
	private String paramName;
	private SourceType sourceType;
	private String sourceName;
	private EncodeType encode; 

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
	public SourceType getSourceType() {
		return sourceType;
	}
	public void setSourceType(SourceType sourceType) {
		this.sourceType = sourceType;
	}
	public String getSourceName() {
		return sourceName;
	}
	public void setSourceName(String sourceName) {
		this.sourceName = sourceName;
	}
	public EncodeType getEncode() {
		return encode;
	}
	public void setEncode(EncodeType encode) {
		this.encode = encode;
	}

	public boolean isSourceReady() {
		return sourceType != null && StringUtils.isNotBlank(sourceName);
	}

}
