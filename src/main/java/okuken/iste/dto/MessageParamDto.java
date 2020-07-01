package okuken.iste.dto;

import burp.IParameter;

public class MessageParamDto {

	private byte type;
	private String name;
	private String value;

	private MessageParamDto() {}
	public static MessageParamDto create(IParameter parameter) {//TODO:converter
		MessageParamDto ret = new MessageParamDto();
		ret.setType(parameter.getType());
		ret.setName(parameter.getName());
		ret.setValue(parameter.getValue());
		return ret;
	}

	public byte getType() {
		return type;
	}
	public void setType(byte type) {
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
	
}
