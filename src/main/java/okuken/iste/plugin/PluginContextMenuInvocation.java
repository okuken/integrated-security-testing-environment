package okuken.iste.plugin;

import java.awt.event.InputEvent;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;

public class PluginContextMenuInvocation implements IContextMenuInvocation {

	@Override
	public int getToolFlag() {
		return IBurpExtenderCallbacks.TOOL_PROXY;
	}

	@Override
	public byte getInvocationContext() {
		return CONTEXT_PROXY_HISTORY;
	}

	@Override
	public IHttpRequestResponse[] getSelectedMessages() {
		return Controller.getInstance().getSelectedMessages().stream()
				.map(MessageDto::getMessage)
				.collect(Collectors.toList())
				.toArray(new IHttpRequestResponse[] {});
	}

	@Override
	public int[] getSelectionBounds() {
		throw new UnsupportedOperationException();
	}
	@Override
	public IScanIssue[] getSelectedIssues() {
		throw new UnsupportedOperationException();
	}
	@Override
	public InputEvent getInputEvent() {
		throw new UnsupportedOperationException();
	}
}
