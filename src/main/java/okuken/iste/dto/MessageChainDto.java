package okuken.iste.dto;

import java.util.List;
import java.util.Optional;

import com.google.common.collect.Lists;

import jakarta.validation.Valid;

public class MessageChainDto {

	private Integer id;
	private Integer messageId; //base message

	@Valid
	private List<MessageChainNodeDto> nodes = Lists.newArrayList();
	@Valid
	private List<MessageChainPresetVarDto> presetVars = Lists.newArrayList();


	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public Integer getMessageId() {
		return messageId;
	}
	public void setMessageId(Integer messageId) {
		this.messageId = messageId;
	}
	public List<MessageChainNodeDto> getNodes() {
		return nodes;
	}
	public void setNodes(List<MessageChainNodeDto> nodes) {
		this.nodes = nodes;
	}
	public List<MessageChainPresetVarDto> getPresetVars() {
		return presetVars;
	}
	public void setPresetVars(List<MessageChainPresetVarDto> presetVars) {
		this.presetVars = presetVars;
	}

	public Optional<MessageChainNodeDto> getMainNode() {
		return nodes.stream().filter(MessageChainNodeDto::isMain).findFirst();
	}

	public boolean isEditedByUser() {
		return !presetVars.isEmpty() || !nodes.isEmpty();
	}

}
