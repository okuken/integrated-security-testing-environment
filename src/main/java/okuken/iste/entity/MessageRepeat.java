package okuken.iste.entity;

import java.util.List;

import okuken.iste.entity.auto.MessageRepeatRedir;

public class MessageRepeat extends okuken.iste.entity.auto.MessageRepeat {

	private List<MessageRepeatRedir> messageRepeatRedirs;

	public List<MessageRepeatRedir> getMessageRepeatRedirs() {
		return messageRepeatRedirs;
	}
	public void setMessageRepeatRedirs(List<MessageRepeatRedir> messageRepeatRedirs) {
		this.messageRepeatRedirs = messageRepeatRedirs;
	}

}
