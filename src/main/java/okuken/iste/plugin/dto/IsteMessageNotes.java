package okuken.iste.plugin.dto;

import okuken.iste.plugin.api.IIsteMessageNotes;

public class IsteMessageNotes implements IIsteMessageNotes {

	private String name;
	private String remark;
	private String priority;

	private Integer progress;
	private String progressNotes;

	private String notes;


	@Override
	public String getName() {
		return name;
	}
	@Override
	public String getRemark() {
		return remark;
	}
	@Override
	public String getPriority() {
		return priority;
	}
	@Override
	public Integer getProgress() {
		return progress;
	}
	@Override
	public String getProgressNotes() {
		return progressNotes;
	}
	@Override
	public String getNotes() {
		return notes;
	}


	public void setName(String name) {
		this.name = name;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	public void setPriority(String priority) {
		this.priority = priority;
	}
	public void setProgress(Integer progress) {
		this.progress = progress;
	}
	public void setProgressNotes(String progressNotes) {
		this.progressNotes = progressNotes;
	}
	public void setNotes(String notes) {
		this.notes = notes;
	}

}
