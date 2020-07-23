package okuken.iste.view.message.table;

import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

public enum MessageTableColumn {

	NAME		("Name",		350,	true),
	REMARK		("Remark",		150,	true),
	PROGRESS	("Progress",	40,		true),
	PROTOCOL	("Protocol",	30,		false),
	HOST		("Host",		80,		false),
	PORT		("Port",		35,		false),
	PATH		("Path",		150,	false),
	QUERY		("Query",		100,	false),
	URL			("URL without Query", 300,	false),
	METHOD		("Method",		35,		false),
	PARAMS		("Params",		25,		false),
	STATUS		("Status",		25,		false),
	LENGTH		("Length",		45,		false),
	MIME_TYPE	("MIME",		45,		false),
	EXTENSION	("Extension", 	25,		false),
	TITLE		("Title", 		100,	false),
	COMMENT		("Comment", 	200,	false),
	TLS			("TLS", 		25,		false),
	IP			("IP", 			25,		false),
	COOKIES		("Cookies", 	400,	false),
	TIME		("Time", 		100,	false);

	private final String caption;
	private final int width;
	private final boolean editable;

	MessageTableColumn(String caption, int width, boolean editable) {
		this.caption = caption;
		this.width = width;
		this.editable = editable;
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

	private static final Map<String, MessageTableColumn> captionToEnumMap;
	static {
		captionToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(column -> captionToEnumMap.put(column.caption, column));
	}
	public static MessageTableColumn getByCaption(String caption) {
		return captionToEnumMap.get(caption);
	}

}
