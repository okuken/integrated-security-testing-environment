package okuken.iste.enums;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum SecurityTestingProgress {

	NOT_YET	(0, "New"),
	DOING	(1, "Work"),
	HOLD	(5, "Hold"),
	ABORT	(8, "Abort"),
	DONE	(9, "Done");

	private Integer id;
	private final String caption;

	private SecurityTestingProgress(Integer id, String caption) {
		this.id = id;
		this.caption = caption;
	}

	public Integer getId() {
		return id;
	}
	public String getCaption() {
		return caption;
	}

	@Override
	public String toString() {
		return caption;
	}

	private static final Map<Integer, SecurityTestingProgress> idToEnumMap;
	static {
		idToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(progress -> idToEnumMap.put(progress.id, progress));
	}
	public static SecurityTestingProgress getById(Integer id) {
		return idToEnumMap.get(id);
	}

}
