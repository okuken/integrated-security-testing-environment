package okuken.iste.view.chain;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.JSplitPane;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.UiUtil;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;

public class ChainRepeaterPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private MessageDto messageDto;

	public ChainRepeaterPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPane_1 = new JSplitPane();
		splitPane_1.setOrientation(JSplitPane.VERTICAL_SPLIT);
		add(splitPane_1);
		
		JPanel headerPanel = new JPanel();
		splitPane_1.setLeftComponent(headerPanel);
		headerPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel repeatTablePanel = new JPanel();
		headerPanel.add(repeatTablePanel, BorderLayout.CENTER);
		
		JPanel controlPanel = new JPanel();
		headerPanel.add(controlPanel, BorderLayout.SOUTH);
		controlPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel controlLeftPanel = new JPanel();
		controlPanel.add(controlLeftPanel, BorderLayout.WEST);
		
		JPanel controlCenterPanel = new JPanel();
		controlPanel.add(controlCenterPanel, BorderLayout.CENTER);
		
		JLabel experimentalFeatureLabel = new JLabel("This is an experimental feature.");
		controlCenterPanel.add(experimentalFeatureLabel);
		
		JPanel controlRightPanel = new JPanel();
		controlPanel.add(controlRightPanel, BorderLayout.EAST);
		
		JButton editChainButton = new JButton(Captions.CHAIN_REPEATER_BUTTON_EDIT_CHAIN);
		editChainButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openChainEditor(editChainButton);
			}
		});
		controlRightPanel.add(editChainButton);
		
		JPanel messageEditorPanel = new JPanel();
		splitPane_1.setRightComponent(messageEditorPanel);

	}

	private void openChainEditor(Component triggerComponent) {
		var chainDefPanel = new ChainDefPanel(messageDto.getId(), Controller.getInstance().getMessageChainIdByBaseMessageId(messageDto.getId()));
		chainDefPanel.setPopupFrame(UiUtil.popup(messageDto.getName() + Captions.CHAIN_REPEATER_POPUP_TITLE_SUFFIX_EDIT_CHAIN, chainDefPanel, triggerComponent, we -> {chainDefPanel.cancel();}));
	}

	public void setup(MessageDto messageDto) {
		this.messageDto = messageDto;
	}

}
