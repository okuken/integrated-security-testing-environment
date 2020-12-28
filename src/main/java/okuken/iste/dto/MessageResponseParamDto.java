package okuken.iste.dto;

import okuken.iste.enums.ResponseParameterType;

public class MessageResponseParamDto {

	private ResponseParameterType type;
	private String name;
	private String value;

	public ResponseParameterType getType() {
		return type;
	}
	public void setType(ResponseParameterType type) {
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
