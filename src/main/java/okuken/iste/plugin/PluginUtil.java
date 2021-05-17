package okuken.iste.plugin;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.dto.burp.HttpRequestResponseMock;
import okuken.iste.dto.burp.HttpServiceMock;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.logic.MessageLogic;
import okuken.iste.plugin.api.IIsteContextMenuFactory;
import okuken.iste.plugin.api.IIsteContextMenuGroup;
import okuken.iste.plugin.api.IIsteContextMenuItem;
import okuken.iste.plugin.api.IIsteContextMenuNode;
import okuken.iste.plugin.api.IIsteExportMessage;
import okuken.iste.plugin.api.IIsteExportRepeatMessage;
import okuken.iste.plugin.api.IIsteImportMessage;
import okuken.iste.plugin.api.IIsteMessage;
import okuken.iste.plugin.api.IIsteMessageAnalyzedInfo;
import okuken.iste.plugin.api.IIsteMessageNotes;
import okuken.iste.plugin.api.IIsteRepeatInfo;
import okuken.iste.plugin.api.IIsteRepeaterContextMenuItem;
import okuken.iste.plugin.dto.IsteExportMessage;
import okuken.iste.plugin.dto.IsteExportRepeatMessage;
import okuken.iste.plugin.dto.IsteMessage;
import okuken.iste.plugin.dto.IsteMessageAnalyzedInfo;
import okuken.iste.plugin.dto.IsteMessageNotes;
import okuken.iste.plugin.dto.IsteRepeatInfo;

public class PluginUtil {

	public static List<JMenuItem> createJMenuItems(IIsteContextMenuFactory factory) {
		List<JMenuItem> ret = Lists.newArrayList();
		factory.createContextMenu().forEach(isteContextMenuNode -> {
			ret.add(createJMenuItemsImpl(isteContextMenuNode));
		});
		return ret;
	}

	private static JMenuItem createJMenuItemsImpl(IIsteContextMenuNode node) {

		if(node instanceof IIsteRepeaterContextMenuItem) {
			var isteRepeaterContextMenuItem = (IIsteRepeaterContextMenuItem) node;
			var jmenuItem = new JMenuItem(isteRepeaterContextMenuItem.getCaption());
			jmenuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					var messageOrgDto = Controller.getInstance().getSelectedMessageRepeatOrg();
					isteRepeaterContextMenuItem.invoke(
							Controller.getInstance().getSelectedMessageRepeats().stream()
								.map(messageRepeatDto -> {
									return convertMessageRepeatDtoToIsteExportRepeatMessage(messageRepeatDto, messageOrgDto);
								})
								.collect(Collectors.toList()));
				}
			});
			return jmenuItem;
		}

		if(node instanceof IIsteContextMenuItem) {
			var isteContextMenuItem = (IIsteContextMenuItem) node;
			var jmenuItem = new JMenuItem(isteContextMenuItem.getCaption());
			jmenuItem.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					isteContextMenuItem.invoke(
							Controller.getInstance().getSelectedMessages().stream()
								.map(PluginUtil::convertMessageDtoToIsteExportMessage)
								.collect(Collectors.toList()));
				}
			});
			return jmenuItem;
		}

		if(node instanceof IIsteContextMenuGroup) {
			var isteContextMenuGroup = (IIsteContextMenuGroup) node;
			var jmenu = new JMenu(isteContextMenuGroup.getCaption());
			var children = isteContextMenuGroup.getChildren();
			if(children == null) {
				return jmenu;
			}
			children.forEach(child -> {
				jmenu.add(createJMenuItemsImpl(child)); //recursive
			});
			return jmenu;
		}

		throw new IllegalArgumentException("not supported IIsteContextMenuNode type: " + node.getClass());
	}


	private static IIsteExportMessage convertMessageDtoToIsteExportMessage(MessageDto messageDto) {
		var ret = new IsteExportMessage();
		ret.setMessage(convertMessageDtoToIsteMessage(messageDto));
		ret.setAnalyzedInfo(convertMessageDtoToIsteMessageAnalyzedInfo(messageDto));
		ret.setNotes(convertMessageDtoToIsteMessageNotes(messageDto));
		return ret;
	}

	private static IIsteExportRepeatMessage convertMessageRepeatDtoToIsteExportRepeatMessage(MessageRepeatDto messageRepeatDto, MessageDto messageOrgDto) {
		var ret = new IsteExportRepeatMessage();

		var messageDto = MessageLogic.getInstance().convertHttpRequestResponseToDto(messageRepeatDto.getMessage());
		ret.setMessage(convertMessageDtoToIsteMessage(messageDto));
		ret.setAnalyzedInfo(convertMessageDtoToIsteMessageAnalyzedInfo(messageDto));

		ret.setNotes(convertMessageDtoToIsteMessageNotes(messageOrgDto));
		ret.setRepeatInfo(convertMessageRepeatDtoToIsteRepeatInfo(messageRepeatDto));

		return ret;
	}

	private static IIsteMessage convertMessageDtoToIsteMessage(MessageDto messageDto) {
		var ret = new IsteMessage();
		ret.setProtocol(messageDto.getProtocol());
		ret.setHost(messageDto.getHost());
		ret.setPort(messageDto.getPort());
		ret.setRequest(messageDto.getRequest() != null ? messageDto.getRequest().clone() : null);
		ret.setResponse(messageDto.getResponse() != null ? messageDto.getResponse().clone() : null);
		return ret;
	}

	private static IIsteMessageAnalyzedInfo convertMessageDtoToIsteMessageAnalyzedInfo(MessageDto messageDto) {
		var ret = new IsteMessageAnalyzedInfo();
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
		return ret;
	}

	private static IIsteMessageNotes convertMessageDtoToIsteMessageNotes(MessageDto messageDto) {
		var ret = new IsteMessageNotes();
		ret.setName(messageDto.getName());
		ret.setRemark(messageDto.getRemark());
		ret.setPriority(messageDto.getPriority());
		ret.setProgress(messageDto.getProgress().getId());
		ret.setProgressNotes(messageDto.getProgressMemo());
		ret.setNotes(messageDto.getMemo());
		return ret;
	}

	private static IIsteRepeatInfo convertMessageRepeatDtoToIsteRepeatInfo(MessageRepeatDto messageRepeatDto) {
		var ret = new IsteRepeatInfo();
		ret.setSendDate(messageRepeatDto.getSendDate());
		ret.setUserId(messageRepeatDto.getUserId());
		ret.setTime(messageRepeatDto.getTime());
		ret.setNotes(messageRepeatDto.getMemo());
		return ret;
	}

	static MessageDto convertIsteImportMessageToMessageDto(IIsteImportMessage isteImportMessage) {
		var ret = MessageLogic.getInstance().convertHttpRequestResponseToDto(convertIsteMessageToHttpRequestResponse(isteImportMessage.getMessage()));
		applyIsteMessageNotesToMessageDto(isteImportMessage.getNotes(), ret);
		return ret;
	}

	private static IHttpRequestResponse convertIsteMessageToHttpRequestResponse(IIsteMessage isteMessage) {
		return new HttpRequestResponseMock(
				isteMessage.getRequest(),
				isteMessage.getResponse(),
				new HttpServiceMock(
						isteMessage.getHost(),
						isteMessage.getPort(),
						isteMessage.getProtocol()));
	}

	private static void applyIsteMessageNotesToMessageDto(IIsteMessageNotes isteMessageNotes, MessageDto messageDto) {
		messageDto.setName(isteMessageNotes.getName());
		messageDto.setRemark(isteMessageNotes.getRemark());
		messageDto.setPriority(isteMessageNotes.getPriority());
		messageDto.setProgress(SecurityTestingProgress.getById(isteMessageNotes.getProgress()));
		messageDto.setProgressMemo(isteMessageNotes.getProgressNotes());
		messageDto.setMemo(isteMessageNotes.getNotes());
	}

}
