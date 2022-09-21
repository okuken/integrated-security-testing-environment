package okuken.iste.entity;

import java.util.List;

import okuken.iste.entity.auto.MessageChain;

public class Message extends okuken.iste.entity.auto.Message {

	private List<MessageChain> messageChains;

	public List<MessageChain> getMessageChains() {
		return messageChains;
	}
	public void setMessageChains(List<MessageChain> messageChains) {
		this.messageChains = messageChains;
	}

}
