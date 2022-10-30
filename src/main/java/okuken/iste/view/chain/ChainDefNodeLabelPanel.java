package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.border.LineBorder;

import okuken.iste.consts.Colors;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpApiUtil;

import java.awt.GridLayout;
import java.awt.event.MouseListener;

import javax.swing.JLabel;

public class ChainDefNodeLabelPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final int NAME_LABEL_LENGTH = 7;

	private MessageDto orgMessageDto;

	private JLabel nameLabel;
	private JLabel orgLabel;
	private JLabel resultLabel;

	public ChainDefNodeLabelPanel(ChainDefNodePanel nodePanel) {
		setLayout(new GridLayout(0, 1, 0, 0));
		setOpaque(true);
		
		nameLabel = new JLabel();
		add(nameLabel);
		
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
		var longStr = orgMessageDto.toString();
		var shortStr = orgMessageDto.toStringShort(NAME_LABEL_LENGTH);

		nameLabel.setText(shortStr);
		nameLabel.setToolTipText(longStr);
		orgLabel.setText(String.format("%s(%d)", orgMessageDto.getStatusStr(), orgMessageDto.getLength()));
		orgLabel.setToolTipText(longStr);
		resultLabel.setText(null);
		resultLabel.setToolTipText(longStr);
	}

	private void refreshByChainResponse(HttpRequestResponseDto message) {
		var response = message.getResponse();
		if(response == null) {
			resultLabel.setText(null);
			return;
		}

		var responseInfo = BurpApiUtil.i().analyzeResponse(response);
		var status = Short.toString(responseInfo.getStatusCode());
		resultLabel.setText(String.format("%s(%d)", status, response.length));

		resultLabel.setForeground(!status.equals(orgMessageDto.getStatusStr()) ? Colors.CHARACTER_ALERT : orgLabel.getForeground());
	}

	void notifyStartChain() {
		resultLabel.setForeground(Colors.CHARACTER_GRAYOUT);
	}

	void addLabelMouseListener(MouseListener listener) {
		nameLabel.addMouseListener(listener);
		orgLabel.addMouseListener(listener);
		resultLabel.addMouseListener(listener);
	}

}
