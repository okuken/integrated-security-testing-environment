package okuken.iste.dto;

public class MessageChainNodeInDto {

	private Integer id;

	private byte paramType; //@see IParameter
	private String paramName;
	private String varName;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public byte getParamType() {
		return paramType;
	}
	public void setParamType(byte paramType) {
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
