package okuken.iste.view.message.table;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import com.google.common.collect.Lists;

import burp.IContextMenuFactory;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.plugin.PluginContextMenuInvocation;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

import java.awt.event.ActionListener;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;

public class MessageTablePopupMenu extends JPopupMenu {

	private static final long serialVersionUID = 1L;

	private List<IContextMenuFactory> pluginContextMenuFactories = Lists.newArrayList();

	public MessageTablePopupMenu() {
		init();
	}
	
	private void init() {
		JMenuItem sendRepeaterRequest = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_REQUEST_REPEATER);
		sendRepeaterRequest.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().sendRepeaterRequest();
			}
		});
		add(sendRepeaterRequest);

		add(new JPopupMenu.Separator());

		JMenuItem doPassiveScanMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_DO_PASSIVE_SCAN);
		doPassiveScanMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().stream()
					.filter(messageDto -> messageDto.getMessage().getResponse() != null)
					.filter(messageDto -> BurpUtil.isInScope(messageDto.getUrl()))
					.forEach(messageDto -> 
						BurpUtil.getCallbacks().doPassiveScan(
							messageDto.getMessage().getHttpService().getHost(),
							messageDto.getMessage().getHttpService().getPort(),
							judgeIsUseHttps(messageDto),
							messageDto.getMessage().getRequest(),
							messageDto.getMessage().getResponse()));
			}
		});
		doPassiveScanMenuItem.setEnabled(BurpUtil.isProfessionalEdition());
		add(doPassiveScanMenuItem);

		JMenuItem doActiveScanMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_DO_ACTIVE_SCAN);
		doActiveScanMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().stream()
					.filter(messageDto -> BurpUtil.isInScope(messageDto.getUrl()))
					.forEach(messageDto -> 
						BurpUtil.getCallbacks().doActiveScan(
							messageDto.getMessage().getHttpService().getHost(),
							messageDto.getMessage().getHttpService().getPort(),
							judgeIsUseHttps(messageDto),
							messageDto.getMessage().getRequest()));
			}
		});
		doActiveScanMenuItem.setEnabled(BurpUtil.isProfessionalEdition());
		add(doActiveScanMenuItem);

		add(new JPopupMenu.Separator());

		JMenuItem sendToIntruderMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_INTRUDER);
		sendToIntruderMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().stream().forEach(messageDto -> 
					BurpUtil.getCallbacks().sendToIntruder(
							messageDto.getMessage().getHttpService().getHost(),
							messageDto.getMessage().getHttpService().getPort(),
							judgeIsUseHttps(messageDto),
							messageDto.getMessage().getRequest()));
			}
		});
		add(sendToIntruderMenuItem);

		JMenuItem sendToRepeaterMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_REPEATER);
		sendToRepeaterMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().stream().forEach(messageDto -> 
					BurpUtil.getCallbacks().sendToRepeater(
							messageDto.getMessage().getHttpService().getHost(),
							messageDto.getMessage().getHttpService().getPort(),
							judgeIsUseHttps(messageDto),
							messageDto.getMessage().getRequest(),
							messageDto.getName()));
			}
		});
		add(sendToRepeaterMenuItem);

		JMenuItem sendToComparerRequestMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST);
		sendToComparerRequestMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().stream().forEach(
						messageDto -> BurpUtil.getCallbacks().sendToComparer(messageDto.getMessage().getRequest()));
			}
		});
		add(sendToComparerRequestMenuItem);

		JMenuItem sendToComparerResponseMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE);
		sendToComparerResponseMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().stream().forEach(
						messageDto -> BurpUtil.getCallbacks().sendToComparer(messageDto.getMessage().getResponse()));
			}
		});
		add(sendToComparerResponseMenuItem);

		if(!pluginContextMenuFactories.isEmpty()) {

			add(new JPopupMenu.Separator());

			pluginContextMenuFactories.forEach(pluginContextMenuFactory -> {
				pluginContextMenuFactory.createMenuItems(new PluginContextMenuInvocation()).forEach(this::add);
			});
		}

		add(new JPopupMenu.Separator());

		JMenuItem deleteItemMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_DELETE_ITEM);
		deleteItemMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(UiUtil.getConfirmAnswer(Captions.MESSAGE_DELETE_ITEM, deleteItemMenuItem)) {
					Controller.getInstance().deleteMessages();
				}
			}
		});
		add(deleteItemMenuItem);

		JMenuItem copyUrlMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_URL);
		copyUrlMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				UiUtil.copyToClipboard(Controller.getInstance().getSelectedMessages().stream()
						.map(messageDto -> messageDto.getUrlShort())
						.collect(Collectors.joining(System.lineSeparator())));
			}
		});
		add(copyUrlMenuItem);

		JMenuItem copyUrlWithoutQueryMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_URL_WITHOUTQUERY);
		copyUrlWithoutQueryMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				UiUtil.copyToClipboard(Controller.getInstance().getSelectedMessages().stream()
						.map(messageDto -> messageDto.getUrlShortest())
						.collect(Collectors.joining(System.lineSeparator())));
			}
		});
		add(copyUrlWithoutQueryMenuItem);

		JMenuItem copyTableMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_TABLE);
		copyTableMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				UiUtil.copyToClipboard(Controller.getInstance().getSelectedMessagesForCopyToClipboad());
			}
		});
		add(copyTableMenuItem);
	}

	private boolean judgeIsUseHttps(MessageDto messageDto) {
		return "https".equals(messageDto.getMessage().getHttpService().getProtocol());
	}

	private void refresh() {
		removeAll();
		init();
	}

	public void addPluginContextMenuFactories(List<IContextMenuFactory> pluginContextMenuFactories) {
		this.pluginContextMenuFactories.addAll(pluginContextMenuFactories);
		refresh();
	}

	public void removePluginContextMenuFactories(List<IContextMenuFactory> pluginContextMenuFactories) {
		this.pluginContextMenuFactories.removeAll(pluginContextMenuFactories);
		refresh();
	}

}
