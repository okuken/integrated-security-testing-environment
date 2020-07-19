package okuken.iste.dto;

import java.util.List;

public class MessageChainNodeDto {

	private Integer id;

	private MessageDto messageDto;

	private List<MessageChainNodeInDto> ins;
	private List<MessageChainNodeOutDto> outs;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public MessageDto getMessageDto() {
		return messageDto;
	}
	public void setMessageDto(MessageDto messageDto) {
		this.messageDto = messageDto;
	}
	public List<MessageChainNodeInDto> getIns() {
		return ins;
	}
	public void setIns(List<MessageChainNodeInDto> ins) {
		this.ins = ins;
	}
	public List<MessageChainNodeOutDto> getOuts() {
		return outs;
	}
	public void setOuts(List<MessageChainNodeOutDto> outs) {
		this.outs = outs;
	}

}
