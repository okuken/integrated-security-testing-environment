package okuken.iste.logic;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageFilterDto;

public class MessageFilterLogic {

	private static final MessageFilterLogic instance = new MessageFilterLogic();
	private MessageFilterLogic() {}
	public static MessageFilterLogic getInstance() {
		return instance;
	}

	public boolean include(MessageDto messageDto, MessageFilterDto filterDto) {
		return filterDto.getProgresses().contains(messageDto.getProgress())
				&& (filterDto.getSearchWord().isEmpty()
					|| StringUtils.containsIgnoreCase(messageDto.getUrlShort(), filterDto.getSearchWord())
					|| StringUtils.containsIgnoreCase(messageDto.getMethod(), filterDto.getSearchWord())
					|| StringUtils.containsIgnoreCase(messageDto.getName(), filterDto.getSearchWord())
					|| StringUtils.containsIgnoreCase(messageDto.getRemark(), filterDto.getSearchWord())
					|| StringUtils.containsIgnoreCase(messageDto.getProgressMemo(), filterDto.getSearchWord()));
	}

	public List<MessageDto> filter(List<MessageDto> messageDtos, MessageFilterDto filterDto) {
		return messageDtos.stream()
				.filter(messageDto -> include(messageDto, filterDto))
				.collect(Collectors.toList());
	}

}
