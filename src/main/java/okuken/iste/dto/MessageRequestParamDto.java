package okuken.iste.dto;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.enums.RequestParameterType;

public class MessageRequestParamDto implements Comparable<MessageRequestParamDto> {

	private RequestParameterType type;
	private String name;
	private String value;

	public MessageRequestParamDto() {}
	public MessageRequestParamDto(RequestParameterType type, String name) {
		this.type = type;
		this.name = name;
	}

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
	public int compareTo(MessageRequestParamDto o) {
		if(type.getId() != o.type.getId()) {
			return type.getId() < o.type.getId() ? -1 : 1;
		}
		return name.compareTo(o.name);
	}

	@Override
	public boolean equals(Object obj) {
		if(this == obj) {
			return true;
		}
		if(obj == null) {
			return false;
		}
		var o = (MessageRequestParamDto)obj;

		return type == o.type &&
				StringUtils.equals(name, o.name);
	}

	@Override
	public String toString() {
		return new StringBuilder()
				.append("[")
				.append(type.getCaption())
				.append("] ")
				.append(name)
				.toString();
	}

}
