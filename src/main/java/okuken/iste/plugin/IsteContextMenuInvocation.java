package okuken.iste.plugin;

import java.util.List;
import java.util.stream.Collectors;

import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.plugin.api.IIsteMessage;
import okuken.iste.plugin.dto.IsteMessage;
import okuken.iste.plugin.api.IIsteContextMenuInvocation;

public class IsteContextMenuInvocation implements IIsteContextMenuInvocation {

	@Override
	public List<IIsteMessage> getSelectedMessages() {
		return Controller.getInstance().getSelectedMessages().stream()
				.map(this::convertMessageDtoToIsteMessage)
				.collect(Collectors.toList());
	}

	private IsteMessage convertMessageDtoToIsteMessage(MessageDto messageDto) {
		var ret = new IsteMessage();

		ret.setProtocol(messageDto.getProtocol());
		ret.setHost(messageDto.getHost());
		ret.setPort(messageDto.getPort());
		ret.setRequest(messageDto.getRequest() != null ? messageDto.getRequest().clone() : null);
		ret.setResponse(messageDto.getResponse() != null ? messageDto.getResponse().clone() : null);

		ret.setUrl(messageDto.getUrlShort());
		ret.setUrlWithoutQuery(messageDto.getUrlShortest());
		ret.setMethod(messageDto.getMethod());
		ret.setPath(messageDto.getPath());
		ret.setQuery(messageDto.getQuery());
		ret.setParamCount(messageDto.getParams());
		ret.setStatus(messageDto.getStatus());
		ret.setLength(messageDto.getLength());
		ret.setMimeType(messageDto.getMimeType());
		ret.setCookies(messageDto.getCookies());

		ret.setName(messageDto.getName());
		ret.setRemark(messageDto.getRemark());
		ret.setPriority(messageDto.getPriority());
		ret.setProgress(messageDto.getProgress().toString());
		ret.setProgressNotes(messageDto.getProgressMemo());
		ret.setNotes(messageDto.getMemo());

		return ret;
	}

}
