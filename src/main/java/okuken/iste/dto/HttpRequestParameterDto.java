package okuken.iste.dto;

import burp.IParameter;

public class HttpRequestParameterDto implements IParameter {

	private byte type;
	private String name;
	private String value;
	private int nameStart;
	private int nameEnd;
	private int valueStart;
	private int valueEnd;

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
	public int getNameStart() {
		return nameStart;
	}
	public void setNameStart(int nameStart) {
		this.nameStart = nameStart;
	}
	public int getNameEnd() {
		return nameEnd;
	}
	public void setNameEnd(int nameEnd) {
		this.nameEnd = nameEnd;
	}
	public int getValueStart() {
		return valueStart;
	}
	public void setValueStart(int valueStart) {
		this.valueStart = valueStart;
	}
	public int getValueEnd() {
		return valueEnd;
	}
	public void setValueEnd(int valueEnd) {
		this.valueEnd = valueEnd;
	}

}
