package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

import burp.IParameter;

public enum RequestParameterType {
	URL				((byte) 0, true,  IParameter.PARAM_URL,            "URL param"),
	BODY			((byte) 1, true,  IParameter.PARAM_BODY,           "Body param"),
	MULTIPART_ATTR	((byte) 5, false, IParameter.PARAM_MULTIPART_ATTR, "Body(Multipart(Attr))"),
	JSON			((byte) 6, false, IParameter.PARAM_JSON,           "Body(JSON)"),
	XML				((byte) 3, false, IParameter.PARAM_XML,            "Body(XML)"),
	XML_ATTR		((byte) 4, false, IParameter.PARAM_XML_ATTR,       "Body(XML(Attr))"),
	COOKIE			((byte) 2, true,  IParameter.PARAM_COOKIE,         "Cookie"),
	HEADER			((byte)80, true,  (byte)80,                        "Header"),
	REGEX			((byte)99, true,  (byte)99,                        "Regex");

	private final byte id;
	private final boolean appliable;
	private final byte burpId;
	private final String caption;

	private RequestParameterType(byte id, boolean appliable, byte burpId, String caption) {
		this.id = id;
		this.appliable = appliable;
		this.burpId = burpId;
		this.caption = caption;
	}

	public byte getId() {
		return id;
	}
	public boolean isAppliable() {
		return appliable;
	}
	public byte getBurpId() {
		return burpId;
	}
	public String getCaption() {
		return caption;
	}

	@Override
	public String toString() {
		return caption;
	}

	private static final Map<Byte, RequestParameterType> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(parameterType -> idToEnumMap.put(parameterType.id, parameterType));
	}
	public static RequestParameterType getById(byte id) {
		return idToEnumMap.get(id);
	}

	private static final Map<Byte, RequestParameterType> burpIdToEnumMap;
	static {
		burpIdToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(parameterType -> burpIdToEnumMap.put(parameterType.burpId, parameterType));
	}
	public static RequestParameterType getByBurpId(byte burpId) {
		return burpIdToEnumMap.get(burpId);
	}

}
