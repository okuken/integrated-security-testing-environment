package okuken.iste.plugin.dto;

import java.util.Date;

import okuken.iste.plugin.api.IIsteRepeatInfo;

public class IsteRepeatInfo implements IIsteRepeatInfo {

	private Date sendDate;
	private String userId;

	private Integer time;

	private String notes;


	@Override
	public Date getSendDate() {
		return sendDate;
	}
	@Override
	public String getUserId() {
		return userId;
	}
	@Override
	public Integer getTime() {
		return time;
	}
	@Override
	public String getNotes() {
		return notes;
	}


	public void setSendDate(Date sendDate) {
		this.sendDate = sendDate;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public void setTime(Integer time) {
		this.time = time;
	}
	public void setNotes(String notes) {
		this.notes = notes;
	}

}
