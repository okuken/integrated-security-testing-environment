package okuken.iste.dto;

import java.util.List;
import java.util.Map;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class MessageChainRepeatDto {

	private int currentIndex = 0;
	private final MessageChainDto messageChainDto;

	private final List<MessageRepeatDto> messageRepeatDtos = Lists.newArrayList();
	private final Map<String, String> vars = Maps.newHashMap();

	public MessageChainRepeatDto(MessageChainDto messageChainDto) {
		super();
		this.messageChainDto = messageChainDto;
	}

	public boolean hasNext() {
		return currentIndex + 1 < messageChainDto.getNodes().size();
	}
	public int next() {
		return ++currentIndex;
	}
	public MessageChainNodeDto getCurrentNodeDto() {
		return messageChainDto.getNodes().get(currentIndex);
	}

	public int getCurrentIndex() {
		return currentIndex;
	}
	public MessageChainDto getMessageChainDto() {
		return messageChainDto;
	}
	public List<MessageRepeatDto> getMessageRepeatDtos() {
		return messageRepeatDtos;
	}
	public Map<String, String> getVars() {
		return vars;
	}

}
