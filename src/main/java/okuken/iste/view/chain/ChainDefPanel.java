package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.BoxLayout;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.UiUtil;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;

public class ChainDefPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private Integer messageId;
	private Integer messageChainId;

	private JFrame popupFrame;
	private JPanel nodesPanel;

	public ChainDefPanel(Integer messageId, Integer messageChainId) {
		this.messageId = messageId;
		this.messageChainId = messageChainId;
		
		setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
		add(scrollPane, BorderLayout.CENTER);
		
		nodesPanel = new JPanel();
		scrollPane.setViewportView(nodesPanel);
		nodesPanel.setLayout(new BoxLayout(nodesPanel, BoxLayout.PAGE_AXIS));
		
		JPanel controlPanel = new JPanel();
		add(controlPanel, BorderLayout.SOUTH);
		controlPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel controlLeftPanel = new JPanel();
		controlPanel.add(controlLeftPanel, BorderLayout.WEST);
		
		JButton cancelButton = new JButton(Captions.CHAIN_DEF_CANCEL);
		controlLeftPanel.add(cancelButton);
		cancelButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				cancel();
			}
		});
		
		JPanel controlCenterPanel = new JPanel();
		controlPanel.add(controlCenterPanel, BorderLayout.CENTER);
		
		JButton testButton = new JButton(Captions.CHAIN_DEF_TEST);
		controlCenterPanel.add(testButton);
		testButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				test();
			}
		});
		
		JPanel controlRightPanel = new JPanel();
		controlPanel.add(controlRightPanel, BorderLayout.EAST);
		
		JButton saveButton = new JButton(Captions.CHAIN_DEF_SAVE);
		controlRightPanel.add(saveButton);
		saveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				save();
			}
		});
		
		init();
	}

	private void init() {
		nodesPanel.add(createAddButtonPanel());
		if(messageChainId == null) {
			return;
		}

		var messageChainDto = Controller.getInstance().loadMessageChain(messageChainId);
		messageChainDto.getNodes().stream().forEach(nodeDto -> {
			addNode(nodeDto, nodesPanel.getComponents().length - 1);
		});
	}

	private JPanel createAddButtonPanel() {
		var buttonPanel = new JPanel();
		((FlowLayout) buttonPanel.getLayout()).setAlignment(FlowLayout.LEFT);

		var addButton = new JButton(Captions.GROUP_CONTROL_BUTTON_ADD);
		buttonPanel.add(addButton);
		addButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				addNode(buttonPanel);
			}
		});

		return buttonPanel;
	}

	private void addNode(JPanel clickedButtonPanel) {
		var index = Arrays.asList(nodesPanel.getComponents()).indexOf(clickedButtonPanel);
		addNode(null, index);
	}
	private void addNode(MessageChainNodeDto nodeDto, int baseIndex) {
		nodesPanel.add(new ChainDefNodePanel(nodeDto, this), baseIndex + 1);
		nodesPanel.add(createAddButtonPanel(), baseIndex + 2);
		UiUtil.repaint(this);
	}

	void removeNode(JPanel clickedNodePanel) {
		var index = Arrays.asList(nodesPanel.getComponents()).indexOf(clickedNodePanel);
		nodesPanel.remove(index); // nodePanel
		nodesPanel.remove(index); // addButtonPanel
		UiUtil.repaint(this);
	}

	private MessageChainDto makeChainDto() {
		var chainDto = new MessageChainDto();

		chainDto.setId(messageChainId);
		chainDto.setNodes(
			Arrays.asList(nodesPanel.getComponents()).stream()
				.filter(component -> component instanceof ChainDefNodePanel)
				.map(nodePanel -> ((ChainDefNodePanel)nodePanel).makeNodeDto())
				.collect(Collectors.toList()));
		chainDto.setMessageId(messageId);

		return chainDto;
	}

	private void test() {
		var chainDefNodePanels = Arrays.asList(nodesPanel.getComponents()).stream()
				.filter(component -> component instanceof ChainDefNodePanel)
				.map(chainDefNodePanel -> (ChainDefNodePanel)chainDefNodePanel)
				.collect(Collectors.toList());

		if(chainDefNodePanels.isEmpty()) {
			return;
		}

		chainDefNodePanels.forEach(nodePanel -> {
			nodePanel.clearMessage();
		});

		var authAccount = judgeIsAuthChain() ? Controller.getInstance().getSelectedAuthAccountOnAuthConfig() : Controller.getInstance().getSelectedAuthAccountOnRepeater();

		Controller.getInstance().sendMessageChain(makeChainDto(), authAccount, (messageChainRepeatDto, index) -> {
			SwingUtilities.invokeLater(() -> {
				chainDefNodePanels.get(index).setMessage(messageChainRepeatDto.getMessageRepeatDtos().get(index).getMessage());
			});
		}, judgeIsAuthChain(),  false);
	}

	private boolean judgeIsAuthChain() {
		return ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainId().equals(messageChainId);
	}

	private void save() {
		var messageChainDto = makeChainDto();
		Controller.getInstance().saveMessageChain(messageChainDto, judgeIsAuthChain());
		messageChainId = messageChainDto.getId();
	}

	private void cancel() {
		UiUtil.closePopup(popupFrame);
	}


	public void setPopupFrame(JFrame popupFrame) {
		this.popupFrame = popupFrame;
	}

}
