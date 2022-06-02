package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.border.LineBorder;

import burp.IHttpRequestResponse;
import okuken.iste.consts.Colors;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;

import java.awt.GridLayout;
import java.awt.event.MouseListener;

import javax.swing.JLabel;

public class ChainDefNodeLabelPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private MessageDto orgMessageDto;

	private JLabel orgLabel;
	private JLabel resultLabel;

	public ChainDefNodeLabelPanel(ChainDefNodePanel nodePanel) {
		setLayout(new GridLayout(0, 1, 0, 0));
		setOpaque(true);
		
		orgLabel = new JLabel();
		add(orgLabel);
		
		resultLabel = new JLabel();
		add(resultLabel);
		
		init(nodePanel);
	}

	private void init(ChainDefNodePanel nodePanel) {

		if(nodePanel.isMainNode()) {
			setBorder(new LineBorder(Colors.BLOCK_BORDER_HIGHLIGHT, 2));
		}

		refreshByMessageSelection(nodePanel.getSelectedMessageDto());
		nodePanel.addMessageSelectionChangeListener(this::refreshByMessageSelection);

		nodePanel.addChainResponseListener(this::refreshByChainResponse);

		nodePanel.addColorChangeListener(this::setBackground);

		nodePanel.addNodeRemoveListener(() -> {
			getParent().remove(this);
		});

	}

	private void refreshByMessageSelection(MessageDto orgMessageDto) {
		this.orgMessageDto = orgMessageDto;
		orgLabel.setText(String.format("%s(%d)", orgMessageDto.getStatusStr(), orgMessageDto.getLength()));
		orgLabel.setToolTipText(orgMessageDto.toString());
		resultLabel.setToolTipText(orgMessageDto.toString());
	}

	private void refreshByChainResponse(IHttpRequestResponse message) {
		var response = message.getResponse();
		if(response == null) {
			resultLabel.setText(null);
			return;
		}

		var responseInfo = BurpUtil.getHelpers().analyzeResponse(response);
		var status = Short.toString(responseInfo.getStatusCode());
		resultLabel.setText(String.format("%s(%d)", status, response.length));

		resultLabel.setForeground(!status.equals(orgMessageDto.getStatusStr()) ? Colors.CHARACTER_ALERT : orgLabel.getForeground());
	}

	void notifyStartChain() {
		resultLabel.setForeground(Colors.CHARACTER_GRAYOUT);
	}

	void addLabelMouseListener(MouseListener listener) {
		orgLabel.addMouseListener(listener);
		resultLabel.addMouseListener(listener);
	}

}
