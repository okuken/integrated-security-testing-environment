package okuken.iste.dto;

import java.util.List;
import java.util.Map;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

public class MessageChainRepeatDto {

	private int currentIndex = 0;
	private final MessageChainDto messageChainDto;

	private boolean breaking;
	private byte[] breakingAppliedRequestForView;
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
		breaking = breakingMessageChainRepeatDto.isBreaking();
		authAccountDto = breakingMessageChainRepeatDto.getAuthAccountDto();
		currentIndex = breakingMessageChainRepeatDto.getCurrentIndex();
		messageRepeatDtos.addAll(breakingMessageChainRepeatDto.getMessageRepeatDtos());
		vars.putAll(breakingMessageChainRepeatDto.getVars());
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


	public boolean isBreaking() {
		return breaking;
	}
	public void setBreaking(boolean breaking) {
		this.breaking = breaking;
	}
	public byte[] getBreakingAppliedRequestForView() {
		return breakingAppliedRequestForView;
	}
	public void setBreakingAppliedRequestForView(byte[] breakingAppliedRequestForView) {
		this.breakingAppliedRequestForView = breakingAppliedRequestForView;
	}
	public boolean isForceTerminate() {
		return forceTerminate;
	}
	public void setForceTerminate(boolean forceTerminate) {
		this.forceTerminate = forceTerminate;
	}

}
