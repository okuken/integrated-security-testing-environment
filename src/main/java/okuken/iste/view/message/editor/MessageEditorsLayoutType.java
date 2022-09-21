package okuken.iste.view.message.editor;

import javax.swing.JSplitPane;

public enum MessageEditorsLayoutType {
	HORIZONTAL_SPLIT("Hor", JSplitPane.HORIZONTAL_SPLIT),
	VERTICAL_SPLIT  ("Ver", JSplitPane.VERTICAL_SPLIT),
	TAB             ("Tab", null);

	private final String caption;
	private final Integer orientation;

	private MessageEditorsLayoutType(String caption, Integer orientation) {
		this.caption = caption;
		this.orientation = orientation;
	}

	public String getCaption() {
		return caption;
	}

	public Integer getOrientation() {
		return orientation;
	}

	@Override
	public String toString() {
		return caption;
	}

}
