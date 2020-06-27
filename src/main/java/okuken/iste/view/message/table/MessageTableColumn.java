package okuken.iste.view.message.table;

public enum MessageTableColumn {

	NAME		("Name",		400,	true),
	HOST		("Host",		100,	false),
	METHOD		("Method",		40,		false),
	URL			("URL",			300,	false),
	PARAMS		("Params",		30,		false),
	STATUS		("Status",		30,		false),
	LENGTH		("Length",		50,		false),
	MIME_TYPE	("MIME",		50,		false),
	EXTENSION	("Extension", 	30,		false),
	TITLE		("Title", 		100,	false),
	COMMENT		("Comment", 	200,	false),
	TLS			("TLS", 		30,		false),
	IP			("IP", 			30,		false),
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
}
