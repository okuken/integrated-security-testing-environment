package okuken.iste.view.repeater;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import com.google.common.collect.Lists;

import burp.IContextMenuFactory;
import burp.IHttpRequestResponse;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.exploit.bsqli.view.BlindSqlInjectionPanel;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

import java.awt.event.ActionListener;
import java.util.List;
import java.util.Optional;
import java.awt.event.ActionEvent;

public class RepeatTablePopupMenu extends JPopupMenu {

	private static final long serialVersionUID = 1L;

	private List<IContextMenuFactory> pluginContextMenuFactories = Lists.newArrayList();

	private RepeatTablePanel parentRepeatTablePanel;

	public RepeatTablePopupMenu(RepeatTablePanel parentRepeatTablePanel) {
		this.parentRepeatTablePanel = parentRepeatTablePanel;
		init();
	}

	private void init() {

		JMenu exploitMenu = new JMenu(Captions.TABLE_CONTEXT_MENU_EXPLOIT_TOOL);
		add(exploitMenu);

		JMenuItem bsqliMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_EXPLOIT_TOOL_BSQLI);
		bsqliMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var orgMessageDto = parentRepeatTablePanel.getParentRepeaterPanel().getOrgMessageDto();
				var selectedRows = parentRepeatTablePanel.getSelectedRows();
				UiUtil.popup(
					orgMessageDto.getName() + Captions.TOOLS_EXPLOIT_BSQLI_POPUP_TITLE_SUFFIX,
					new BlindSqlInjectionPanel(orgMessageDto.getId(), selectedRows.get(selectedRows.size() - 1).getMessage(), true),
					parentRepeatTablePanel);
			}
		});
		exploitMenu.add(bsqliMenuItem);

		add(new JPopupMenu.Separator());

		JMenuItem sendToComparerRequestMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST);
		sendToComparerRequestMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				parentRepeatTablePanel.getSelectedRows().stream().forEach(
						dto -> BurpUtil.getCallbacks().sendToComparer(nvl(dto.getMessage().getRequest())));
			}
		});
		add(sendToComparerRequestMenuItem);

		JMenuItem sendToComparerRequestWithOrgMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST_WITH_ORG);
		sendToComparerRequestWithOrgMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				BurpUtil.getCallbacks().sendToComparer(nvl(getOrgMessage().getRequest()));
				parentRepeatTablePanel.getSelectedRows().stream().forEach(
						dto -> BurpUtil.getCallbacks().sendToComparer(nvl(dto.getMessage().getRequest())));
			}
		});
		add(sendToComparerRequestWithOrgMenuItem);

		JMenuItem sendToComparerRequestWithMasterMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_REQUEST_WITH_MST);
		sendToComparerRequestWithMasterMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				BurpUtil.getCallbacks().sendToComparer(nvl(getMasterMessage().getRequest()));
				parentRepeatTablePanel.getSelectedRows().stream().forEach(
						dto -> BurpUtil.getCallbacks().sendToComparer(nvl(dto.getMessage().getRequest())));
			}
		});
		add(sendToComparerRequestWithMasterMenuItem);

		JMenuItem sendToComparerResponseMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE);
		sendToComparerResponseMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				parentRepeatTablePanel.getSelectedRows().stream().forEach(
						dto -> BurpUtil.getCallbacks().sendToComparer(nvl(dto.getMessage().getResponse())));
			}
		});
		add(sendToComparerResponseMenuItem);

		JMenuItem sendToComparerResponseWithOrgMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE_WITH_ORG);
		sendToComparerResponseWithOrgMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				BurpUtil.getCallbacks().sendToComparer(nvl(getOrgMessage().getResponse()));
				parentRepeatTablePanel.getSelectedRows().stream().forEach(
						dto -> BurpUtil.getCallbacks().sendToComparer(nvl(dto.getMessage().getResponse())));
			}
		});
		add(sendToComparerResponseWithOrgMenuItem);

		JMenuItem sendToComparerResponseWithMasterMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_TO_COMPARER_RESPONSE_WITH_MST);
		sendToComparerResponseWithMasterMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				BurpUtil.getCallbacks().sendToComparer(nvl(getMasterMessage().getResponse()));
				parentRepeatTablePanel.getSelectedRows().stream().forEach(
						dto -> BurpUtil.getCallbacks().sendToComparer(nvl(dto.getMessage().getResponse())));
			}
		});
		add(sendToComparerResponseWithMasterMenuItem);

		//TODO: impl
//		if(!pluginContextMenuFactories.isEmpty()) {
//
//			add(new JPopupMenu.Separator());
//
//			pluginContextMenuFactories.forEach(pluginContextMenuFactory -> {
//				pluginContextMenuFactory.createMenuItems(new PluginContextMenuInvocation()).forEach(this::add);
//			});
//		}

//		add(new JPopupMenu.Separator());
//
		//TODO:impl
//		JMenuItem deleteItemMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_DELETE_ITEM);
//		deleteItemMenuItem.addActionListener(new ActionListener() {
//			public void actionPerformed(ActionEvent e) {
//				if(UiUtil.getConfirmAnswer(Captions.MESSAGE_DELETE_ITEM, deleteItemMenuItem)) {
//					Controller.getInstance().deleteMessages();
//				}
//			}
//		});
//		add(deleteItemMenuItem);
		
		
		Controller.getInstance().setRepeatTablePopupMenu(this);
	}

	private void refresh() {
		removeAll();
		init();
	}

	private IHttpRequestResponse getOrgMessage() {
		return parentRepeatTablePanel.getParentRepeaterPanel().getOrgMessageDto().getMessage();
	}
	private IHttpRequestResponse getMasterMessage() {
		return parentRepeatTablePanel.getParentRepeaterPanel().getMasterMessage();
	}
	private byte[] nvl(byte[] bytes) {
		return Optional.ofNullable(bytes).orElse(new byte[] {});
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
