package okuken.iste.enums;

import java.awt.Color;
import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum SecurityTestingProgress {

	NOT_YET	(0, "New",   Color.WHITE),
	DOING	(1, "Work",  Color.ORANGE),
	HOLD	(5, "Hold",  Color.CYAN),
	ABORT	(8, "Abort", Color.GRAY),
	DONE	(9, "Done",  Color.LIGHT_GRAY);

	private final Integer id;
	private final String caption;
	private final Color color;

	private SecurityTestingProgress(Integer id, String caption, Color color) {
		this.id = id;
		this.caption = caption;
		this.color = color;
	}

	public Integer getId() {
		return id;
	}
	public String getCaption() {
		return caption;
	}
	public Color getColor() {
		return color;
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

	private static final Map<String, SecurityTestingProgress> captionToEnumMap;
	static {
		captionToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(progress -> captionToEnumMap.put(progress.caption, progress));
	}
	public static SecurityTestingProgress getByCaption(String caption) {
		return captionToEnumMap.get(caption);
	}

}
