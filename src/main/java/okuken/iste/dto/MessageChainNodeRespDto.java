package okuken.iste.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import okuken.iste.enums.ResponseParameterType;

public class MessageChainNodeRespDto {

	private Integer id;

	@NotNull
	private ResponseParameterType paramType;
	@NotEmpty
	private String paramName;
	@NotEmpty
	private String varName;

	public MessageChainNodeRespDto() {}
	public MessageChainNodeRespDto(ResponseParameterType paramType, String paramName, String varName) {
		this.paramType = paramType;
		this.paramName = paramName;
		this.varName = varName;
	}

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public ResponseParameterType getParamType() {
		return paramType;
	}
	public void setParamType(ResponseParameterType paramType) {
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
