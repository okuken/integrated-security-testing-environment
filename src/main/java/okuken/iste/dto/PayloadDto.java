package okuken.iste.dto;

public class PayloadDto {

	private String targetParamName;
	private byte targetParamType; //@see IParameter

	private String payload;

	public PayloadDto() {}
	public PayloadDto(String targetParamName, byte targetParamType, String payload) {
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
	public byte getTargetParamType() {
		return targetParamType;
	}
	public void setTargetParamType(byte targetParamType) {
		this.targetParamType = targetParamType;
	}
	public String getPayload() {
		return payload;
	}
	public void setPayload(String payload) {
		this.payload = payload;
	}

}
