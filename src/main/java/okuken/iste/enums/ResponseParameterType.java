package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum ResponseParameterType {
	BODY			((byte) 1, false, "Body"),
	JSON			((byte) 6, false, "Body(JSON)"),
	COOKIE			((byte) 2, true,  "Cookie"),
	HTML_TAG		((byte)95, true,  "HTML tag"),
	REGEX			((byte)99, true,  "Regex");

	private final byte id;
	private final boolean extractable;
	private final String caption;

	private ResponseParameterType(byte id, boolean extractable, String caption) {
		this.id = id;
		this.extractable = extractable;
		this.caption = caption;
	}

	public byte getId() {
		return id;
	}
	public boolean isExtractable() {
		return extractable;
	}
	public String getCaption() {
		return caption;
	}

	@Override
	public String toString() {
		return caption;
	}

	public ExtractType getExtractType() {
		switch (this) {
		case REGEX:
			return ExtractType.REGEX;
		case HTML_TAG:
			return ExtractType.HTML_TAG;
		default:
			return null;
		}
	}

	private static final Map<Byte, ResponseParameterType> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(parameterType -> idToEnumMap.put(parameterType.id, parameterType));
	}
	public static ResponseParameterType getById(byte id) {
		return idToEnumMap.get(id);
	}

}
