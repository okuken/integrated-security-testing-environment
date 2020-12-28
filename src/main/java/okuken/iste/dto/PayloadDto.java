package okuken.iste.dto;

import okuken.iste.enums.RequestParameterType;

public class PayloadDto {

	private String targetParamName;
	private RequestParameterType targetParamType;

	private String payload;

	public PayloadDto() {}
	public PayloadDto(String targetParamName, RequestParameterType targetParamType, String payload) {
		this();
		this.targetParamName = targetParamName;
		this.targetParamType = targetParamType;
		this.payload = payload;
	}

	public String getTargetParamName() {
		return targetParamName;
	}
	public void setTargetParamName(String targetParamName) {
		this.targetParamName = targetParamName;
	}
	public RequestParameterType getTargetParamType() {
		return targetParamType;
	}
	public void setTargetParamType(RequestParameterType targetParamType) {
		this.targetParamType = targetParamType;
	}
	public String getPayload() {
		return payload;
	}
	public void setPayload(String payload) {
		this.payload = payload;
	}

}
