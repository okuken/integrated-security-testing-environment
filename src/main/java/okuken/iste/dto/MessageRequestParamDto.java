package okuken.iste.dto;

import okuken.iste.enums.RequestParameterType;

public class MessageRequestParamDto {

	private RequestParameterType type;
	private String name;
	private String value;

	public RequestParameterType getType() {
		return type;
	}
	public void setType(RequestParameterType type) {
		this.type = type;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}

	@Override
	public String toString() {
		return name;
	}

}
