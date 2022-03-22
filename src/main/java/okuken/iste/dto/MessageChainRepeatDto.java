package okuken.iste.dto;

import java.util.List;
import java.util.Map;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class MessageChainRepeatDto {

	private int currentIndex = 0;
	private final MessageChainDto messageChainDto;

	private byte[] nextAppliedRequestForView;
	private volatile boolean forceTerminate;

	private AuthAccountDto authAccountDto;

	private final List<MessageRepeatDto> messageRepeatDtos = Lists.newArrayList();
	private final Map<String, String> vars = Maps.newHashMap();

	public MessageChainRepeatDto(MessageChainDto messageChainDto, AuthAccountDto authAccountDto) {
		super();
		this.messageChainDto = messageChainDto;
		messageChainDto.getPresetVars().forEach(dto -> {vars.put(dto.getName(), dto.getValue());});
		this.authAccountDto = authAccountDto;
	}

	public void applyBreakingInfo(MessageChainRepeatDto breakingMessageChainRepeatDto) {
		authAccountDto = breakingMessageChainRepeatDto.getAuthAccountDto();
		currentIndex = breakingMessageChainRepeatDto.getCurrentIndex() + 1;
		nextAppliedRequestForView = breakingMessageChainRepeatDto.getNextAppliedRequestForView();
		messageRepeatDtos.addAll(breakingMessageChainRepeatDto.getMessageRepeatDtos());
		vars.putAll(breakingMessageChainRepeatDto.getVars());
	}

	public boolean canNext() {
		var nextIndex = currentIndex + 1;
		if(nextIndex < messageChainDto.getNodes().size()) {
			return !messageChainDto.getNodes().get(nextIndex).isBreakpoint();
		};
		return false;
	}
	public boolean hasNext() {
		return currentIndex + 1 < messageChainDto.getNodes().size();
	}
	public int next() {
		return ++currentIndex;
	}
	public int before() {
		return --currentIndex;
	}
	public MessageChainNodeDto getCurrentNodeDto() {
		return messageChainDto.getNodes().get(currentIndex);
	}
	public MessageChainNodeDto getNextNodeDto() {
		return messageChainDto.getNodes().get(currentIndex + 1);
	}

	public int getCurrentIndex() {
		return currentIndex;
	}
	public MessageChainDto getMessageChainDto() {
		return messageChainDto;
	}
	public AuthAccountDto getAuthAccountDto() {
		return authAccountDto;
	}
	public List<MessageRepeatDto> getMessageRepeatDtos() {
		return messageRepeatDtos;
	}
	public Map<String, String> getVars() {
		return vars;
	}

	public byte[] getNextAppliedRequestForView() {
		return nextAppliedRequestForView;
	}
	public void setNextAppliedRequestForView(byte[] nextAppliedRequestForView) {
		this.nextAppliedRequestForView = nextAppliedRequestForView;
	}
	public boolean isForceTerminate() {
		return forceTerminate;
	}
	public void setForceTerminate(boolean forceTerminate) {
		this.forceTerminate = forceTerminate;
	}

}
