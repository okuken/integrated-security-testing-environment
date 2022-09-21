package okuken.iste.enums;

import java.awt.Color;

import okuken.iste.consts.Colors;
import okuken.iste.logic.ConfigLogic;

public enum IsteColor {

	BLOCK_BACKGROUND_HIGHLIGHT	(Colors.BURP_COLOR,		Colors.BURP_COLOR),
	BLOCK_BACKGROUND_GRAYOUT	(Color.GRAY,			new Color(0x808080)),
	BLOCK_BACKGROUND_HOLD		(new Color(0x83BAD6),	new Color(0x283C63));

	private final Color colorLightTheme;
	private final Color colorDarkTheme;

	private IsteColor(Color colorLightTheme, Color colorDarkTheme) {
		this.colorLightTheme = colorLightTheme;
		this.colorDarkTheme = colorDarkTheme;
	}

	public Color get() {
		if(ConfigLogic.getInstance().getUserOptions().isDarkTheme()) {
			return colorDarkTheme;
		}
		return colorLightTheme;
	}

}