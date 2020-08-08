package okuken.iste.view.message.table;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

import okuken.iste.dto.MessageDto;
import okuken.iste.enums.SecurityTestingProgress;

public enum MessageTableColumn {

	NAME		("Name",			350,		true,  "getName",							"setName",							String.class),
	REMARK		("Remark",			100,		true,  "getRemark",							"setRemark",						String.class),
	AUTH		("Auth",			30,			true,  "getAuthMatrix",						"setAuthMatrix",					String.class),
	PRIORITY	("Priority",		15,			true,  "getPriority",						"setPriority",						String.class),
	PROGRESS	("Progress",		40,			true,  "getProgress",						"setProgress",						SecurityTestingProgress.class),
	PROGRESS_MEMO("Progress memo",	60,			true,  "getProgressMemo",					"setProgressMemo",					String.class),
	PROGRESS_TECHNICAL		("T",	18,			true,  "getProgressTechnical", 				"setProgressTechnical",				String.class),
	PROGRESS_LOGICAL		("L",	18,			true,  "getProgressLogical",				"setProgressLogical",				String.class),
	PROGRESS_AUTHENTICATION	("A",	18,			true,  "getProgressAuthentication",			"setProgressAuthentication",		String.class),
	PROGRESS_AUTH_FEATURE	("F",	18,			true,  "getProgressAuthorizationFeature",	"setProgressAuthorizationFeature",	String.class),
	PROGRESS_AUTH_RESOURCE	("R",	18,			true,  "getProgressAuthorizationResource",	"setProgressAuthorizationResource",	String.class),
	PROGRESS_CSRF			("C",	18,			true,  "getProgressCsrf", 					"setProgressCsrf",					String.class),
	PROTOCOL	("Protocol",		30,			false, "getProtocol",						null,null),
	HOST		("Host",			80,			false, "getHost",							null,null),
	PORT		("Port",			35,			false, "getPortIfNotDefaultStr",			null,null),
	PATH		("Path",			150,		false, "getPath",							null,null),
	QUERY		("Query",			50,			false, "getQuery",							null,null),
	URL			("URL without Query", 300,		false, "getUrlShortest",					null,null),
	METHOD		("Method",			35,			false, "getMethod",							null,null),
	PARAMS		("Params",			25,			false, "getParamsStr",						null,null),
	STATUS		("Status",			25,			false, "getStatusStr",						null,null),
	LENGTH		("Length",			45,			false, "getLengthStr",						null,null),
	MIME_TYPE	("MIME",			45,			false, "getMimeType",						null,null),
	COOKIES		("Cookies",			400,		false, "getCookies",						null,null);

	private final String caption;
	private final int width;
	private final boolean editable;
	private final Method getter;
	private final Method setter;

	MessageTableColumn(String caption, int width, boolean editable, String getterName, String setterName, Class<?> type) {
		this.caption = caption;
		this.width = width;
		this.editable = editable;

		try {
			if(getterName != null) {
				this.getter = MessageDto.class.getMethod(getterName);
			} else {
				this.getter = null;
			}

			if(setterName != null) {
				this.setter = MessageDto.class.getMethod(setterName, type);
			} else {
				this.setter = null;
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
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

	private static final Map<String, MessageTableColumn> captionToEnumMap;
	static {
		captionToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(column -> captionToEnumMap.put(column.caption, column));
	}
	public static MessageTableColumn getByCaption(String caption) {
		return captionToEnumMap.get(caption);
	}

}
