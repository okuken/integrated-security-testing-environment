package okuken.iste.enums;

import java.awt.Color;
import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

import okuken.iste.logic.ConfigLogic;

public enum SecurityTestingProgress {

	NOT_YET	(0, "New",   Color.WHITE,         new Color(0x2B2B2B)),
	DOING	(1, "Work",  new Color(0xDF907C), new Color(0xB30753)),
	HOLD	(5, "Hold",  new Color(0x83BAD6), new Color(0x283C63)),
	ABORT	(8, "Abort", Color.GRAY,          new Color(0x808080)),
	DONE	(9, "Done",  Color.LIGHT_GRAY,    new Color(0x45494A));

	private final Integer id;
	private final String caption;
	private final Color colorLightTheme;
	private final Color colorDarkTheme;

	private SecurityTestingProgress(Integer id, String caption, Color colorLightTheme, Color colorDarkTheme) {
		this.id = id;
		this.caption = caption;
		this.colorLightTheme = colorLightTheme;
		this.colorDarkTheme = colorDarkTheme;
	}

	public Integer getId() {
		return id;
	}
	public String getCaption() {
		return caption;
	}
	public Color getColor() {
		if(ConfigLogic.getInstance().getUserOptions().isDarkTheme()) {
			return colorDarkTheme;
		}
		return colorLightTheme;
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
		if(id == null) {
			return NOT_YET;
		}

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
