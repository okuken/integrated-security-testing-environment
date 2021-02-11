package okuken.iste.dto;

import java.util.List;

public class MessageChainNodeDto {

	private Integer id;

	private MessageDto messageDto;

	private List<MessageChainNodeReqpDto> reqps;
	private List<MessageChainNodeRespDto> resps;

	private byte[] editedRequest;

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
	public List<MessageChainNodeReqpDto> getReqps() {
		return reqps;
	}
	public void setReqps(List<MessageChainNodeReqpDto> reqps) {
		this.reqps = reqps;
	}
	public List<MessageChainNodeRespDto> getResps() {
		return resps;
	}
	public void setResps(List<MessageChainNodeRespDto> resps) {
		this.resps = resps;
	}
	public byte[] getEditedRequest() {
		return editedRequest;
	}
	public void setEditedRequest(byte[] editedRequest) {
		this.editedRequest = editedRequest;
	}

	public byte[] getRequest() {
		if(editedRequest != null) {
			return editedRequest;
		}
		return messageDto.getMessage().getRequest();
	}

}
