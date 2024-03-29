package okuken.iste.dto;

import jakarta.validation.constraints.NotEmpty;

public class MessageChainPresetVarDto {

	private Integer id;

	@NotEmpty
	private String name;
	private String value;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
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
