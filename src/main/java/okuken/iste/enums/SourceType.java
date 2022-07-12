package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum SourceType {
	VAR                ((byte) 0, "Var"          , false),
	AUTH_ACCOUNT_TABLE ((byte) 1, "Account table", false);

	private final byte id;
	private final String caption;
	private final boolean authOnly;

	private SourceType(byte id, String caption, boolean authOnly) {
		this.id = id;
		this.caption = caption;
		this.authOnly = authOnly;
	}

	public byte getId() {
		return id;
	}
	public String getCaption() {
		return caption;
	}
	public boolean isAuthOnly() {
		return authOnly;
	}

	@Override
	public String toString() {
		return caption;
	}

	private static final Map<Byte, SourceType> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(parameterType -> idToEnumMap.put(parameterType.id, parameterType));
	}
	public static SourceType getById(byte id) {
		return idToEnumMap.get(id);
	}

}
