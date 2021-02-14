package okuken.iste.view.chain;

import javax.swing.JPanel;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.view.message.editor.MessageEditorPanel;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;

import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.border.LineBorder;

import burp.IHttpRequestResponse;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class ChainDefNodePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final Dimension MESSAGE_EDITOR_PREFERRED_SIZE = new Dimension(800, 400);

	private ChainDefPanel parentChainDefPanel;

	private boolean isMainNode;

	private JComboBox<MessageDto> urlComboBox;
	private ChainDefNodeRequestParamsPanel requestParamsPanel;
	private ChainDefNodeResponseParamsPanel responseParamsPanel;

	private MessageEditorPanel messageEditorPanel;

	private boolean refreshingFlag = false;

	public ChainDefNodePanel(MessageChainNodeDto nodeDto, ChainDefPanel parentChainDefPanel) {
		this.parentChainDefPanel = parentChainDefPanel;
		this.isMainNode = nodeDto != null && nodeDto.isMain();
		
		setLayout(new BorderLayout(0, 0));
		setBorder(new LineBorder(Color.GRAY));
		
		JPanel centerPanel = new JPanel(new BorderLayout(0, 0));
		add(centerPanel, BorderLayout.CENTER);
		
		JPanel panel = new JPanel(new BorderLayout(0, 0));
		centerPanel.add(panel, BorderLayout.WEST);
		
		JPanel mainPanel = new JPanel();
		panel.add(mainPanel, BorderLayout.NORTH);
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.PAGE_AXIS));
		
		JPanel urlPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) urlPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		mainPanel.add(urlPanel);
		
		urlComboBox = new JComboBox<MessageDto>();
		urlComboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if(!refreshingFlag && e.getStateChange() == ItemEvent.SELECTED) {
					refreshMessageEditorPanel();
				}
			}
		});
		urlComboBox.setEnabled(!isMainNode);
		urlPanel.add(urlComboBox);
		
		requestParamsPanel = new ChainDefNodeRequestParamsPanel();
		FlowLayout flowLayout_1 = (FlowLayout) requestParamsPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.LEFT);
		mainPanel.add(requestParamsPanel);
		
		responseParamsPanel = new ChainDefNodeResponseParamsPanel();
		FlowLayout flowLayout_2 = (FlowLayout) responseParamsPanel.getLayout();
		flowLayout_2.setAlignment(FlowLayout.LEFT);
		mainPanel.add(responseParamsPanel);
		
		messageEditorPanel = new MessageEditorPanel(null, !parentChainDefPanel.judgeIsAuthChain(), false, true);
		centerPanel.add(messageEditorPanel, BorderLayout.CENTER);
		messageEditorPanel.setPreferredSize(MESSAGE_EDITOR_PREFERRED_SIZE);
		
		JPanel leftPanel = new JPanel();
		add(leftPanel, BorderLayout.WEST);
		
		JButton btnDelete = new JButton(Captions.CHAIN_DEF_NODE_BUTTON_DELETE);
		btnDelete.setToolTipText(Captions.CHAIN_DEF_NODE_BUTTON_DELETE_TT);
		btnDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				removeNode();
			}
		});
		btnDelete.setEnabled(!isMainNode);
		leftPanel.add(btnDelete);
		
		initPanel(nodeDto);
	}

	private void initPanel(MessageChainNodeDto nodeDto) {
		refreshPanel(nodeDto, Controller.getInstance().getMessages());
	}

	public void refreshPanel(MessageChainNodeDto nodeDto, List<MessageDto> messageDtos) {
		var refreshingFlagBk = refreshingFlag;
		refreshingFlag = true;
		try {
			urlComboBox.removeAllItems();
			urlComboBox.setMaximumRowCount(Sizes.MAX_ROW_COUNT_COMBOBOX);
			messageDtos.forEach(messageDto -> {
				urlComboBox.addItem(messageDto);
			});

			if(nodeDto == null) {
				refreshMessageEditorPanel();
				return;
			}

			urlComboBox.setSelectedItem(messageDtos.stream().filter(messageDto -> messageDto.getId().equals(nodeDto.getMessageDto().getId())).findFirst().get());
			refreshMessageEditorPanel();

			nodeDto.getReqps().stream().forEach(reqpDto -> {
				requestParamsPanel.addRow(reqpDto);
			});
			nodeDto.getResps().stream().forEach(respDto -> {
				responseParamsPanel.addRow(respDto);
			});

		} finally {
			refreshingFlag = refreshingFlagBk;
		}
	}

	private void refreshMessageEditorPanel() {
		messageEditorPanel.setMessage(urlComboBox.getItemAt(urlComboBox.getSelectedIndex()));
	}

	private void removeNode() {
		parentChainDefPanel.removeNode(this);
	}

	public MessageChainNodeDto makeNodeDto() {
		//TODO: validation
		var nodeDto = new MessageChainNodeDto();
		nodeDto.setMain(isMainNode);
		nodeDto.setMessageDto(urlComboBox.getItemAt(urlComboBox.getSelectedIndex()));
		nodeDto.setReqps(requestParamsPanel.getRows());
		nodeDto.setResps(responseParamsPanel.getRows());
		nodeDto.setEditedRequest(messageEditorPanel.getRequest());
		return nodeDto;
	}

	public void clearMessage() {
		messageEditorPanel.clearMessage();
	}
	public void setMessage(IHttpRequestResponse message) {
		messageEditorPanel.setMessage(message);
	}

}
