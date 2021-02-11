package okuken.iste.dto;

import java.util.List;

import com.google.common.collect.Lists;

public class MessageChainNodeDto {

	private Integer id;

	private MessageDto messageDto;

	private List<MessageChainNodeReqpDto> reqps = Lists.newArrayList();
	private List<MessageChainNodeRespDto> resps = Lists.newArrayList();

	private boolean main;

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
	public boolean isMain() {
		return main;
	}
	public void setMain(boolean main) {
		this.main = main;
	}

	public byte[] getRequest() {
		if(editedRequest != null) {
			return editedRequest;
		}
		return messageDto.getMessage().getRequest();
	}

}
