package okuken.iste.view.chain;

import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;

import org.jsoup.nodes.Attributes;
import org.jsoup.nodes.Element;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Positions;
import okuken.iste.dto.MessageChainTokenTransferSettingDto;
import okuken.iste.dto.MessageRequestParamDto;

import javax.swing.JComboBox;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.List;
import java.awt.event.ActionEvent;

public class ChainDefTokenTransferSettingPanel extends JPanel {

	private static final String[] PRIORITY_KEY_ATTR_NAME_HIDDEN = new String[] {"name", "id"};
	private static final String[] PRIORITY_VAL_ATTR_NAME_HIDDEN = new String[] {"value"};

	private static final String[] PRIORITY_KEY_ATTR_NAME_META = new String[] {"name"};
	private static final String[] PRIORITY_VAL_ATTR_NAME_META = new String[] {"content"};

	private static final String[] KEYWORDS = new String[] {"TOKEN", "CSRF", "XSRF"};

	private static final long serialVersionUID = 1L;

	private Element element;
	private String baseSelector;
	private List<MessageRequestParamDto> chainRequestParams;

	private JCheckBox tagCheckBox;
	private JLabel keyAttrNameLabel;
	private JComboBox<String> keyAttrNameComboBox;
	private JLabel valueAttrNameLabel;
	private JComboBox<String> valAttrNameComboBox;
	private JLabel requestParamNameLabel;
	private JComboBox<MessageRequestParamDto> requestParamComboBox;

	public ChainDefTokenTransferSettingPanel(Element element, String baseSelector, List<MessageRequestParamDto> chainRequestParams) {
		this.element = element;
		this.baseSelector = baseSelector;
		this.chainRequestParams = chainRequestParams;
		
		var tag = element.toString();
		tagCheckBox = new JCheckBox(tag);
		tagCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				refresh();
			}
		});
		
		keyAttrNameLabel = new JLabel(Captions.CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_ATTR_NAME_KEY + ":");
		
		keyAttrNameComboBox = new JComboBox<String>();
		
		valueAttrNameLabel = new JLabel(Captions.CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_ATTR_NAME_VALUE + ":");
		
		valAttrNameComboBox = new JComboBox<String>();
		
		requestParamNameLabel = new JLabel(Captions.CHAIN_DEF_SEMIAUTO_SETTING_TOKEN_REQUEST_PARAM_NAME + ":");
		
		requestParamComboBox = new JComboBox<MessageRequestParamDto>();
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(tagCheckBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(Positions.INDENT_GAP)
							.addComponent(keyAttrNameLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(keyAttrNameComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(valueAttrNameLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(valAttrNameComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(Positions.INDENT_GAP)
							.addComponent(requestParamNameLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(requestParamComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(tagCheckBox)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(valAttrNameComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(keyAttrNameLabel)
						.addComponent(keyAttrNameComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(valueAttrNameLabel))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(requestParamNameLabel)
						.addComponent(requestParamComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
					.addContainerGap())
		);
		setLayout(groupLayout);


		setDetailVisible(false);

		var tagUpperCase = tag.toUpperCase();
		if(Arrays.stream(KEYWORDS).anyMatch(keyword -> tagUpperCase.contains(keyword))) {
			tagCheckBox.setForeground(Colors.CHARACTER_HIGHLIGHT);
			tagCheckBox.setSelected(true);
			refresh();
		}

	}

	private void refresh() {
		var selected = tagCheckBox.isSelected();

		setDetailVisible(selected);
		if(selected) {
			refreshDetail();
		}
	}

	private void refreshDetail() {
		refreshAttrNameComboBox();
		refreshRequestParamsComboBox();
	}

	private void refreshAttrNameComboBox() {
		keyAttrNameComboBox.removeAllItems();
		valAttrNameComboBox.removeAllItems();

		var attributes = element.attributes();
		attributes.forEach(attr -> {
			keyAttrNameComboBox.addItem(attr.getKey());
			valAttrNameComboBox.addItem(attr.getKey());
		});

		if(baseSelector == ChainDefTokenTransferSettingsPanel.BASE_SELECTOR_HIDDEN) {
			keyAttrNameComboBox.setSelectedItem(extractByPriority(attributes, PRIORITY_KEY_ATTR_NAME_HIDDEN));
			valAttrNameComboBox.setSelectedItem(extractByPriority(attributes, PRIORITY_VAL_ATTR_NAME_HIDDEN));
		} else if(baseSelector == ChainDefTokenTransferSettingsPanel.BASE_SELECTOR_META) {
			keyAttrNameComboBox.setSelectedItem(extractByPriority(attributes, PRIORITY_KEY_ATTR_NAME_META));
			valAttrNameComboBox.setSelectedItem(extractByPriority(attributes, PRIORITY_VAL_ATTR_NAME_META));
		}
	}

	private void refreshRequestParamsComboBox() {
		requestParamComboBox.removeAllItems();
		requestParamComboBox.addItem(null);

		chainRequestParams.forEach(requestParamComboBox::addItem);

		var keyAttrValue = extractKeyAttrValue();
		var matchParam = chainRequestParams.stream().filter(param -> param.getName().equals(keyAttrValue)).findFirst();
		if(matchParam.isPresent()) {
			requestParamComboBox.setSelectedItem(matchParam.get());
		}
	}

	private String extractKeyAttrValue() {
		var keyAttrName = keyAttrNameComboBox.getItemAt(keyAttrNameComboBox.getSelectedIndex());
		return element.attr(keyAttrName);
	}

	private String extractByPriority(Attributes attributes, String[] priority) {
		for(var key: priority) {
			if(attributes.hasKey(key)) {
				return key;
			}
		}
		return attributes.iterator().next().getKey();
	}

	private void setDetailVisible(boolean visible) {
		keyAttrNameLabel.setVisible(visible);
		keyAttrNameComboBox.setVisible(visible);
		valueAttrNameLabel.setVisible(visible);
		valAttrNameComboBox.setVisible(visible);
		requestParamNameLabel.setVisible(visible);
		requestParamComboBox.setVisible(visible);
	}

	boolean isSelected() {
		return tagCheckBox.isSelected();
	}

	MessageChainTokenTransferSettingDto createDto() {
		return new MessageChainTokenTransferSettingDto(
				baseSelector,
				element, 
				keyAttrNameComboBox.getItemAt(keyAttrNameComboBox.getSelectedIndex()),
				valAttrNameComboBox.getItemAt(valAttrNameComboBox.getSelectedIndex()),
				requestParamComboBox.getItemAt(requestParamComboBox.getSelectedIndex()));
	}

}
