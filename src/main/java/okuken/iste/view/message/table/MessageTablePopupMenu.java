package okuken.iste.view.message.table;

import javax.swing.Action;
import javax.swing.JComboBox;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.KeyStroke;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.exploit.bsqli.view.BlindSqlInjectionPanel;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.TemplateLogic;
import okuken.iste.plugin.PluginPopupMenuListener;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.AbstractAction;
import okuken.iste.view.chain.ChainDefPanel;
import okuken.iste.view.message.editor.MessageCellEditorDialog;
import okuken.iste.view.message.selector.MessageSelectorForCreateChain;

import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;

public class MessageTablePopupMenu extends JPopupMenu {

	private static final long serialVersionUID = 1L;

	static final KeyStroke KEYSTROKE_SENDTO_INTRUDER = KeyStroke.getKeyStroke(KeyEvent.VK_I, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_SENDTO_REPEATER = KeyStroke.getKeyStroke(KeyEvent.VK_R, ActionEvent.CTRL_MASK, false);

	static final KeyStroke KEYSTROKE_EDIT_CELL = KeyStroke.getKeyStroke(KeyEvent.VK_E, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_DELETE_ITEM = KeyStroke.getKeyStroke(KeyEvent.VK_D, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_COPY_NAME = KeyStroke.getKeyStroke(KeyEvent.VK_N, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_COPY_NAME_WITHOUT_NUMBER = KeyStroke.getKeyStroke(KeyEvent.VK_N, ActionEvent.CTRL_MASK | ActionEvent.SHIFT_MASK, false);
	static final KeyStroke KEYSTROKE_COPY_URL = KeyStroke.getKeyStroke(KeyEvent.VK_U, ActionEvent.CTRL_MASK, false);
	static final KeyStroke KEYSTROKE_COPY_URL_WITHOUT_QUERY = KeyStroke.getKeyStroke(KeyEvent.VK_U, ActionEvent.CTRL_MASK | ActionEvent.SHIFT_MASK, false);

	private JPanel parentPanel;
	private JTable table;

	private PluginPopupMenuListener pluginPopupMenuListener;
	private JPopupMenu.Separator pluginMenuItemsStartSeparator;

	public MessageTablePopupMenu(JPanel parentPanel, JTable table) {
		this.parentPanel = parentPanel;
		this.table = table;
		init();

		pluginPopupMenuListener = new PluginPopupMenuListener(this, pluginMenuItemsStartSeparator);
		addPopupMenuListener(pluginPopupMenuListener);
	}

	@SuppressWarnings("serial")
	private void init() {
		JMenuItem sendRepeaterRequest = new JMenuItem(Captions.TABLE_CONTEXT_MENU_SEND_REQUEST_REPEATER);
		sendRepeaterRequest.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().sendRepeaterRequest(UiUtil.judgeIsForceRefresh(e));
			}
		});
		add(sendRepeaterRequest);

		JMenu exploitMenu = new JMenu(Captions.TABLE_CONTEXT_MENU_EXPLOIT_TOOL);
		add(exploitMenu);

		JMenuItem bsqliMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_EXPLOIT_TOOL_BSQLI);
		bsqliMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var selectedMessages = Controller.getInstance().getSelectedMessages();
				var selectedMessage = selectedMessages.get(selectedMessages.size() - 1);
				UiUtil.popup(
					selectedMessage.getName() + Captions.TOOLS_EXPLOIT_BSQLI_POPUP_TITLE_SUFFIX,
					new BlindSqlInjectionPanel(selectedMessage.getId(), selectedMessage.getMessage(), true),
					parentPanel);
			}
		});
		exploitMenu.add(bsqliMenuItem);

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
		UiUtil.setupTablePopupMenuItem(sendToIntruderMenuItem, table, KEYSTROKE_SENDTO_INTRUDER, new AbstractAction() {
			public void actionPerformedSafe(ActionEvent e) {
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
		UiUtil.setupTablePopupMenuItem(sendToRepeaterMenuItem, table, KEYSTROKE_SENDTO_REPEATER, new AbstractAction() {
			public void actionPerformedSafe(ActionEvent e) {
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

		pluginMenuItemsStartSeparator = new JPopupMenu.Separator();
		add(pluginMenuItemsStartSeparator);

		add(new JPopupMenu.Separator());

		JMenuItem openChainMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_OPEN_CHAIN);
		openChainMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().getSelectedMessages().forEach(orgMessageDto -> {
					ChainDefPanel.openChainFrame(orgMessageDto, table);
				});
			}
		});
		add(openChainMenuItem);

		JMenuItem createChainMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_CREATE_CHAIN);
		createChainMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var selectedMessages = Controller.getInstance().getSelectedMessages();
				var targetMessage = selectedMessages.size() == 1 ? selectedMessages.get(0) : MessageSelectorForCreateChain.showDialog(selectedMessages);
				if(targetMessage == null) {
					return;
				}

				var chain = Controller.getInstance().getMessageChainByBaseMessageId(targetMessage.getId());
				if(chain != null && chain.isEditedByUser()) {
					if(!UiUtil.getConfirmAnswer(Captions.MESSAGE_SELECT_CREATE_CHAIN_TARGET_EXIST, table)) {
						return;
					}
				}

				var chainDefPanel = new ChainDefPanel(targetMessage, chain != null ? chain.getId() : null, selectedMessages, true);
				chainDefPanel.setPopupFrame(UiUtil.popup(targetMessage.getName() + Captions.REPEATER_POPUP_TITLE_SUFFIX_CHAIN, chainDefPanel, table, we -> {chainDefPanel.cancel();}));
			}
		});
		add(createChainMenuItem);

		JMenuItem createAuthChainMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_CREATE_AUTH_CHAIN);
		createAuthChainMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var selectedMessages = Controller.getInstance().getSelectedMessages();

				var chain = ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainDto();
				if(chain.isEditedByUser()) {
					if(!UiUtil.getConfirmAnswer(Captions.MESSAGE_AUTH_CHAIN_EXIST, table)) {
						return;
					}
				}

				var chainDefPanel = new ChainDefPanel(null, chain.getId(), selectedMessages, true);
				chainDefPanel.setPopupFrame(UiUtil.popup(Captions.AUTH_CONFIG_POPUP_TITLE_EDIT_CHAIN, chainDefPanel, table, we -> {chainDefPanel.cancel();}));
			}
		});
		add(createAuthChainMenuItem);

		add(new JPopupMenu.Separator());

		JMenuItem editCellMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_EDIT_CELL);
		UiUtil.setupTablePopupMenuItem(editCellMenuItem, table, KEYSTROKE_EDIT_CELL, new AbstractAction() {
			public void actionPerformedSafe(ActionEvent e) {
				var selectedMessages = Controller.getInstance().getSelectedMessages();
				if(selectedMessages.isEmpty()) {
					return;
				}

				var columnType = Controller.getInstance().getSelectedMessageColumnType();
				if(!columnType.isEditable()) {
					UiUtil.showMessage("Selected column is not editable.", parentPanel);
					return;
				}

				var burpFrame = BurpUtil.getBurpSuiteJFrame();
				if(columnType.getType() == SecurityTestingProgress.class) {
					var progressComboBox = new JComboBox<SecurityTestingProgress>();
					Arrays.stream(SecurityTestingProgress.values()).forEach(progress -> progressComboBox.addItem(progress));
					progressComboBox.setSelectedItem(selectedMessages.get(0).getProgress());
					if(UiUtil.showOptionDialog(
							burpFrame,
							progressComboBox,
							columnType.getCaption(),
							JOptionPane.OK_CANCEL_OPTION,
							JOptionPane.PLAIN_MESSAGE, null, null, null) == 0) {

						var progress = progressComboBox.getItemAt(progressComboBox.getSelectedIndex());
						selectedMessages.forEach(message -> {
							message.setProgress(progress);
							Controller.getInstance().updateMessage(message, false);
						});
						Controller.getInstance().applyMessageFilter();
					}
					return;
				}

				var messageCellEditorDialog = new MessageCellEditorDialog(burpFrame, selectedMessages, columnType);
				BurpUtil.getCallbacks().customizeUiComponent(messageCellEditorDialog);
				messageCellEditorDialog.setLocationRelativeTo(burpFrame);
				messageCellEditorDialog.setVisible(true);
			}
		});
		add(editCellMenuItem);

		JMenuItem deleteItemMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_DELETE_ITEM);
		UiUtil.setupTablePopupMenuItem(deleteItemMenuItem, table, KEYSTROKE_DELETE_ITEM, new AbstractAction() {
			public void actionPerformedSafe(ActionEvent e) {
				if(UiUtil.getConfirmAnswerDefaultCancel(Captions.MESSAGE_DELETE_ITEM, deleteItemMenuItem)) {
					Controller.getInstance().deleteMessages();
				}
			}
		});
		add(deleteItemMenuItem);

		JMenuItem copyNameMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_NAME);
		UiUtil.setupTablePopupMenuItem(copyNameMenuItem, table, KEYSTROKE_COPY_NAME,
			createActionForCopy(messageDto -> messageDto.getName()));
		add(copyNameMenuItem);

		JMenuItem copyNameWithoutNumberMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_NAME_WITHOUTNUMBER);
		UiUtil.setupTablePopupMenuItem(copyNameWithoutNumberMenuItem, table, KEYSTROKE_COPY_NAME_WITHOUT_NUMBER,
			createActionForCopy(messageDto -> messageDto.getNameWithoutNumber()));
		add(copyNameWithoutNumberMenuItem);

		JMenuItem copyUrlMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_URL);
		UiUtil.setupTablePopupMenuItem(copyUrlMenuItem, table, KEYSTROKE_COPY_URL,
			createActionForCopy(messageDto -> messageDto.getUrlShort()));
		add(copyUrlMenuItem);

		JMenuItem copyUrlWithoutQueryMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_URL_WITHOUTQUERY);
		UiUtil.setupTablePopupMenuItem(copyUrlWithoutQueryMenuItem, table, KEYSTROKE_COPY_URL_WITHOUT_QUERY,
			createActionForCopy(messageDto -> messageDto.getUrlShortest()));
		add(copyUrlWithoutQueryMenuItem);

		JMenuItem copyTableMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_TABLE);
		copyTableMenuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				UiUtil.copyToClipboard(Controller.getInstance().getSelectedMessagesForCopyToClipboad());
			}
		});
		add(copyTableMenuItem);


		var loadedCopyTemplates = ConfigLogic.getInstance().getUserOptions().getCopyTemplates();
		if(loadedCopyTemplates != null) {

			add(new JPopupMenu.Separator());

			var loadedCopyTemplateMnemonics = ConfigLogic.getInstance().getUserOptions().getCopyTemplateMnemonics();
			loadedCopyTemplates.entrySet().forEach(template -> {
				JMenuItem menuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_BY_TEMPLATE_PREFIX + template.getKey());
				menuItem.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						UiUtil.copyToClipboard(Controller.getInstance().getSelectedMessages().stream()
								.map(messageDto -> TemplateLogic.getInstance().evaluateTemplate(template.getValue(), messageDto))
								.collect(Collectors.joining(System.lineSeparator())));
					}
				});
				if(loadedCopyTemplateMnemonics != null && loadedCopyTemplateMnemonics.containsKey(template.getKey()) && StringUtils.isNotBlank(loadedCopyTemplateMnemonics.get(template.getKey()))) {
					menuItem.setMnemonic(
						(int)loadedCopyTemplateMnemonics.get(template.getKey()).charAt(0));
				}
				add(menuItem);
			});
		}

	}

	private boolean judgeIsUseHttps(MessageDto messageDto) {
		return "https".equals(messageDto.getMessage().getHttpService().getProtocol());
	}

	@SuppressWarnings("serial")
	private Action createActionForCopy(Function<MessageDto, String> mapper) {
		return new AbstractAction() {
			public void actionPerformedSafe(ActionEvent e) {
				UiUtil.copyToClipboard(Controller.getInstance().getSelectedMessages().stream()
						.map(messageDto -> Optional.ofNullable(mapper.apply(messageDto)).orElse(""))
						.collect(Collectors.joining(System.lineSeparator())));
			}
		};
	}

	public void refresh() {
		removeAll();
		init();
	}

	public PluginPopupMenuListener getPluginPopupMenuListener() {
		return pluginPopupMenuListener;
	}

}
