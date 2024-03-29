package okuken.iste.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import okuken.iste.enums.EncodeType;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;

public class MessageChainNodeReqpDto {

	private Integer id;

	@NotNull
	private RequestParameterType paramType;
	@NotEmpty
	private String paramName;
	@NotNull
	private SourceType sourceType;
	@NotEmpty
	private String sourceName;
	private EncodeType encode = EncodeType.NONE;

	public MessageChainNodeReqpDto() {}
	public MessageChainNodeReqpDto(RequestParameterType paramType, String paramName, SourceType sourceType, String sourceName) {
		this.paramType = paramType;
		this.paramName = paramName;
		this.sourceType = sourceType;
		this.sourceName = sourceName;
	}

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
	public EncodeType getEncode() {
		return encode;
	}
	public void setEncode(EncodeType encode) {
		this.encode = encode;
	}

}
