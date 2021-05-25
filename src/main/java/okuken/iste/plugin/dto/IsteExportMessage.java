package okuken.iste.plugin.dto;

import okuken.iste.plugin.api.IIsteExportMessage;
import okuken.iste.plugin.api.IIsteMessage;
import okuken.iste.plugin.api.IIsteMessageAnalyzedInfo;
import okuken.iste.plugin.api.IIsteMessageNotes;

public class IsteExportMessage implements IIsteExportMessage {

	private IIsteMessage message;
	private IIsteMessageAnalyzedInfo analyzedInfo;
	private IIsteMessageNotes notes;


	@Override
	public IIsteMessage getMessage() {
		return message;
	}
	@Override
	public IIsteMessageAnalyzedInfo getAnalyzedInfo() {
		return analyzedInfo;
	}
	@Override
	public IIsteMessageNotes getNotes() {
		return notes;
	}


	public void setMessage(IIsteMessage message) {
		this.message = message;
	}
	public void setAnalyzedInfo(IIsteMessageAnalyzedInfo analyzedInfo) {
		this.analyzedInfo = analyzedInfo;
	}
	public void setNotes(IIsteMessageNotes notes) {
		this.notes = notes;
	}

}
