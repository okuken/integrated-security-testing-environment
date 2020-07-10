package okuken.iste.dto;

import okuken.iste.consts.Captions;

public class ProjectDto {

	private Integer id;
	private String name;
	private String explanation;

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
	public String getExplanation() {
		return explanation;
	}
	public void setExplanation(String explanation) {
		this.explanation = explanation;
	}

	@Override
	public String toString() {
		if(id == null) {
			return Captions.SELECT_PROJECT_NEW;
		}
		return String.format("[%d] %s", id, name);
	}

}
