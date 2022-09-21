package okuken.iste.dto;

import org.jsoup.nodes.Element;

public class MessageChainTokenTransferSettingDto {

	public static final String SETTING_SEPARATER = ";";

	private final String baseSelector;
	private final Element element;
	private final String keyAttrName;
	private final String valueAttrName;

	private final MessageRequestParamDto requestParam;

	private final String varName;
	private final String selector;
	private final String settingString;

	public MessageChainTokenTransferSettingDto(String baseSelector, Element element,
			String keyAttrName, String valueAttrName, MessageRequestParamDto requestParam) {
		this.baseSelector = baseSelector;
		this.element = element;
		this.keyAttrName = keyAttrName;
		this.valueAttrName = valueAttrName;
		this.requestParam = requestParam;

		varName = element != null ? element.attr(keyAttrName) : "";

		selector = new StringBuilder()
				.append(baseSelector)
				.append("[")
				.append(keyAttrName)
				.append("=")
				.append(varName)
				.append("]")
				.toString();

		settingString = new StringBuilder()
				.append(selector)
				.append(SETTING_SEPARATER)
				.append(valueAttrName)
				.toString();
	}

	public String getBaseSelector() {
		return baseSelector;
	}
	public Element getElement() {
		return element;
	}
	public String getKeyAttrName() {
		return keyAttrName;
	}
	public String getValueAttrName() {
		return valueAttrName;
	}
	public MessageRequestParamDto getRequestParam() {
		return requestParam;
	}


	public String getVarName() {
		return varName;
	}
	public String getSelector() {
		return selector;
	}
	public String getSettingString() {
		return settingString;
	}

}
