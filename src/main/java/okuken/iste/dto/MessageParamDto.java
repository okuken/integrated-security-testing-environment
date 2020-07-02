package okuken.iste.dto;

public class MessageParamDto {

	private byte type;
	private String name;
	private String value;

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
