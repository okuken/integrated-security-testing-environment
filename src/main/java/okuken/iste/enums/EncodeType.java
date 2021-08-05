package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum EncodeType {
	NONE(0, ""),
	URL (1, "URL-encode");

	private final int id;
	private final String caption;

	private EncodeType(int id, String caption) {
		this.id = id;
		this.caption = caption;
	}

	public int getId() {
		return id;
	}
	public String getCaption() {
		return caption;
	}

	@Override
	public String toString() {
		return caption;
	}

	private static final Map<Integer, EncodeType> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(type -> idToEnumMap.put(type.id, type));
	}
	public static EncodeType getById(int id) {
		return idToEnumMap.get(id);
	}

}
