package okuken.iste.dto;

import java.util.List;

import okuken.iste.enums.SecurityTestingProgress;

public class MessageFilterDto {

	private List<SecurityTestingProgress> progresses;

	public List<SecurityTestingProgress> getProgresses() {
		return progresses;
	}
	public void setProgresses(List<SecurityTestingProgress> progresses) {
		this.progresses = progresses;
	}

}
