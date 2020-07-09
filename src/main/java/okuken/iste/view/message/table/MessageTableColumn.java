package okuken.iste.view.message.table;

public enum MessageTableColumn {

	NAME		("Name",		300,	true),
	REMARK		("Remark",		150,	true),
	PROTOCOL	("Protocol",	50,		false),
	HOST		("Host",		80,		false),
	PORT		("Port",		40,		false),
	PATH		("Path",		100,	false),
	QUERY		("Query",		100,	false),
	URL			("URL without Query", 300,	false),
	METHOD		("Method",		40,		false),
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
