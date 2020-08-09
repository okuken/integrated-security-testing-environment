package okuken.iste.enums;

import burp.IParameter;

public enum ParameterType {
	URL				(IParameter.PARAM_URL,				"URL"),
	BODY			(IParameter.PARAM_BODY,				"Body"),
	MULTIPART_ATTR	(IParameter.PARAM_MULTIPART_ATTR,	"Body(Multipart)"),
	JSON			(IParameter.PARAM_JSON,				"Body(JSON)"),
	XML				(IParameter.PARAM_XML,				"Body(XML)"),
	XML_ATTR		(IParameter.PARAM_XML_ATTR,			"Body(XML(Attr))"),
	COOKIE			(IParameter.PARAM_COOKIE,			"Cookie");

	private final byte id;
	private final String caption;

	private ParameterType(byte id, String caption) {
		this.id = id;
		this.caption = caption;
	}

	public byte getId() {
		return id;
	}
	public String getCaption() {
		return caption;
	}

	@Override
	public String toString() {
		return caption;
	}

}
