package okuken.iste.dto;

import java.util.List;

import com.google.common.collect.Lists;

import jakarta.validation.Valid;

public class MessageChainNodeDto {

	private Integer id;

	private MessageDto messageDto;

	@Valid
	private List<MessageChainNodeReqpDto> reqps = Lists.newArrayList();
	@Valid
	private List<MessageChainNodeRespDto> resps = Lists.newArrayList();

	private boolean main;

	private boolean breakpoint;
	private boolean skip;

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
	public boolean isBreakpoint() {
		return breakpoint;
	}
	public void setBreakpoint(boolean breakpoint) {
		this.breakpoint = breakpoint;
	}
	public boolean isSkip() {
		return skip;
	}
	public void setSkip(boolean skip) {
		this.skip = skip;
	}

	public byte[] getRequest() {
		if(editedRequest != null) {
			return editedRequest;
		}
		return messageDto.getMessage().getRequest();
	}

	public boolean hasSettings() {
		return !reqps.isEmpty() || !resps.isEmpty() || breakpoint || skip;
	}

}
