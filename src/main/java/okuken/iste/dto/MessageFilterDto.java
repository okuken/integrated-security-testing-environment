package okuken.iste.dto;

import java.util.List;

import okuken.iste.enums.SecurityTestingProgress;

public class MessageFilterDto {

	private String searchWord;
	private List<SecurityTestingProgress> progresses;

	public String getSearchWord() {
		return searchWord;
	}
	public void setSearchWord(String searchWord) {
		this.searchWord = searchWord;
	}
	public List<SecurityTestingProgress> getProgresses() {
		return progresses;
	}
	public void setProgresses(List<SecurityTestingProgress> progresses) {
		this.progresses = progresses;
	}

}
