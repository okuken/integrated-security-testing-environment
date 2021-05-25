package okuken.iste.plugin.dto;

import okuken.iste.plugin.api.IIsteExportRepeatMessage;
import okuken.iste.plugin.api.IIsteRepeatInfo;

public class IsteExportRepeatMessage extends IsteExportMessage implements IIsteExportRepeatMessage {

	private IIsteRepeatInfo repeatInfo;

	@Override
	public IIsteRepeatInfo getRepeatInfo() {
		return repeatInfo;
	}

	public void setRepeatInfo(IIsteRepeatInfo repeatInfo) {
		this.repeatInfo = repeatInfo;
	}

}
