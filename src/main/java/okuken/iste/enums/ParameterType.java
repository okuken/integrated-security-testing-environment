package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

import burp.IParameter;

public enum ParameterType {
	URL				(IParameter.PARAM_URL,				"URL"),
	BODY			(IParameter.PARAM_BODY,				"Body"),
	MULTIPART_ATTR	(IParameter.PARAM_MULTIPART_ATTR,	"Body(Multipart)"),
	JSON			(IParameter.PARAM_JSON,				"Body(JSON)"),
	XML				(IParameter.PARAM_XML,				"Body(XML)"),
	XML_ATTR		(IParameter.PARAM_XML_ATTR,			"Body(XML(Attr))"),
	COOKIE			(IParameter.PARAM_COOKIE,			"Cookie"),
	REGEX			((byte)99,							"Regex");

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

	private static final Map<Byte, ParameterType> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(parameterType -> idToEnumMap.put(parameterType.id, parameterType));
	}
	public static ParameterType getById(byte id) {
		return idToEnumMap.get(id);
	}

}
