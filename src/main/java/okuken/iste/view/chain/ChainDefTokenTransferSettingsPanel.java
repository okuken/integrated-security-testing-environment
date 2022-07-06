package okuken.iste.view.chain;

import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainTokenTransferSettingDto;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.MessageUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.common.VerticalFlowPanel;

import java.awt.Component;
import java.awt.Dimension;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class ChainDefTokenTransferSettingsPanel extends JPanel {

	static final String BASE_SELECTOR_HIDDEN = "input[type=hidden]";
	static final String BASE_SELECTOR_META = "meta";
	static final String[] BASE_SELECTORS = {BASE_SELECTOR_HIDDEN, BASE_SELECTOR_META};

	private static final long serialVersionUID = 1L;

	private MessageChainDto chainDto;

	private VerticalFlowPanel mainPanel;

	public ChainDefTokenTransferSettingsPanel(MessageChainDto chainDto) {
		this.chainDto = chainDto;
		
		setPreferredSize(new Dimension(600, 400));
		setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBorder(null);
		add(scrollPane);
		
		JPanel panel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) panel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		scrollPane.setViewportView(panel);
		
		mainPanel = new VerticalFlowPanel();
		mainPanel.setAlignLeft();
		panel.add(mainPanel);

		init();
	}

	private void init() {
		var chainRequestParams = MessageUtil.extractRequestParams(chainDto.getNodes().stream().map(MessageChainNodeDto::getMessageDto).collect(Collectors.toList()));

		for(var chainNode: chainDto.getNodes()) {
			if(chainNode.getMessageDto().getResponseInfo() == null) {
				continue;
			}

			var docOptional = MessageUtil.parseResponseHtml(chainNode.getMessageDto());
			if(docOptional.isEmpty()) {
				continue;
			}
			var doc = docOptional.get();

			Arrays.stream(BASE_SELECTORS).forEach(baseSelector -> {
				doc.select(baseSelector).stream()
					.filter(element -> element.attributesSize() > 0)
					.forEach(element -> {
						mainPanel.add(new ChainDefTokenTransferSettingPanel(element, baseSelector, chainRequestParams));
					});
			});
		}
	}

	public List<MessageChainTokenTransferSettingDto> showDialog(Component parent) {
		if(mainPanel.getComponentCount() <= 0) {
			UiUtil.showMessage(Captions.MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_TOKEN_EMPTY, this);
			return null;
		}
		BurpUtil.getCallbacks().customizeUiComponent(this);

		if(UiUtil.showOptionDialog(
				parent,
				this,
				Captions.MESSAGE_SELECT_SEMIAUTO_SETTING_TARGET_TOKEN,
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null) == 0) {

			return Arrays.stream(mainPanel.getComponents())
					.map(c -> (ChainDefTokenTransferSettingPanel)c)
					.filter(settingPanel -> settingPanel.isSelected())
					.map(settingPanel -> settingPanel.createDto())
					.collect(Collectors.toList());

		}
		return null;
	}

}
