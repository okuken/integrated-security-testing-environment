package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum OrderType {

	AUTH_ACCOUNT      (0),
	AUTH_APPLY_CONFIG (1);

	private final Integer id;

	private OrderType(Integer id) {
		this.id = id;
	}

	public Integer getId() {
		return id;
	}

	private static final Map<Integer, OrderType> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(value -> idToEnumMap.put(value.id, value));
	}
	public static OrderType getById(Integer id) {
		return idToEnumMap.get(id);
	}

}
