package okuken.iste.dto;

import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;

public class MessageChainNodeReqpDto {

	private Integer id;

	private RequestParameterType paramType;
	private String paramName;
	private SourceType sourceType;
	private String sourceName;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
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

}
