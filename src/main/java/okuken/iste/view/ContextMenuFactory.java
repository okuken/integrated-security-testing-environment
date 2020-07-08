package okuken.iste.view;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;

public class ContextMenuFactory implements IContextMenuFactory {

	private ContextMenuFactory() {}
	public static ContextMenuFactory create() {
		return new ContextMenuFactory();
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
		if (selectedMessages == null) {
			return null;
		}

		return Arrays.asList(createSendToMenu(selectedMessages));
	}

	private JMenuItem createSendToMenu(IHttpRequestResponse[] selectedMessages) {
		JMenuItem ret = new JMenuItem(Captions.CONTEXT_MENU_SEND_TO, KeyEvent.VK_S);

		ret.addActionListener((ActionEvent e) -> {
			Controller.getInstance().sendMessagesToSuiteTab(Arrays.stream(selectedMessages)
					.filter(message -> message.getRequest() != null)
					.collect(Collectors.toList()));
		});

		return ret;
	}

}