package okuken.iste.view.common;

import java.lang.reflect.Method;

public class ColumnDef {

	private final int index;
	private final String caption;
	private final int width;
	private final boolean editable;
	private final Method getter;
	private final Method setter;
	private final Class<?> type;

	public ColumnDef(int index, String caption, int width) {
		this.index = index;
		this.caption = caption;
		this.width = width;

		editable = false;
		getter = null;
		setter = null;
		type = String.class;
	}

	public ColumnDef(int index, String caption, int width, boolean editable, String getterName, String setterName, Class<?> type, Class<?> dtoClass) {
		this.index = index;
		this.caption = caption;
		this.width = width;
		this.editable = editable;
		this.type = type;

		try {
			if(getterName != null) {
				this.getter = dtoClass.getMethod(getterName);
			} else {
				this.getter = null;
			}

			if(setterName != null) {
				this.setter = dtoClass.getMethod(setterName, type);
			} else {
				this.setter = null;
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public int getIndex() {
		return index;
	}
	public String getCaption() {
		return caption;
	}
	public int getWidth() {
		return width;
	}
	public boolean isEditable() {
		return editable;
	}
	public Method getGetter() {
		return getter;
	}
	public Method getSetter() {
		return setter;
	}
	public Class<?> getType() {
		return type;
	}

}
