package okuken.iste.view.message.table;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;

import com.google.common.collect.Maps;

import okuken.iste.dto.MessageDto;
import okuken.iste.enums.SecurityTestingProgress;

public enum MessageTableColumn {

	NAME		("Name",			350,		true,  false, "getName",							"setName",							String.class),
	REMARK		("Remark",			100,		true,  false, "getRemark",							"setRemark",						String.class),
	AUTH		("Auth",			30,			true,  false, "getAuthMatrix",						"setAuthMatrix",					String.class),
	PRIORITY	("Priority",		15,			true,  false, "getPriority",						"setPriority",						String.class),
	PROGRESS	("Progress",		40,			true,  false, "getProgress",						"setProgress",						SecurityTestingProgress.class),
	PROGRESS_MEMO("Progress notes",	60,			true,  false, "getProgressMemo",					"setProgressMemo",					String.class),
	PROGRESS_TECHNICAL		("T",	18,			true,  true,  "getProgressTechnical", 				"setProgressTechnical",				String.class),
	PROGRESS_LOGICAL		("L",	18,			true,  true,  "getProgressLogical",					"setProgressLogical",				String.class),
	PROGRESS_AUTHENTICATION	("A",	18,			true,  true,  "getProgressAuthentication",			"setProgressAuthentication",		String.class),
	PROGRESS_AUTH_FEATURE	("F",	18,			true,  true,  "getProgressAuthorizationFeature",	"setProgressAuthorizationFeature",	String.class),
	PROGRESS_AUTH_RESOURCE	("R",	18,			true,  true,  "getProgressAuthorizationResource",	"setProgressAuthorizationResource",	String.class),
	PROGRESS_CSRF			("C",	18,			true,  true,  "getProgressCsrf", 					"setProgressCsrf",					String.class),
	PROTOCOL	("Protocol",		30,			false, false, "getProtocol",						null,								String.class),
	HOST		("Host",			80,			false, false, "getHost",							null,								String.class),
	PORT		("Port",			35,			false, false, "getPortIfNotDefaultStr",				null,								String.class),
	PATH		("Path",			150,		false, false, "getPath",							null,								String.class),
	QUERY		("Query",			50,			false, false, "getQuery",							null,								String.class),
	URL			("URL without Query", 300,		false, false, "getUrlShortest",						null,								String.class),
	METHOD		("Method",			35,			false, false, "getMethod",							null,								String.class),
	PARAMS		("Params",			25,			false, false, "getParamsStr",						null,								String.class),
	STATUS		("Status",			25,			false, false, "getStatusStr",						null,								String.class),
	LENGTH		("Length",			45,			false, false, "getLengthStr",						null,								String.class),
	MIME_TYPE	("MIME",			45,			false, false, "getMimeType",						null,								String.class),
	COOKIES		("Cookies",			400,		false, false, "getCookies",							null,								String.class);

	private final String caption;
	private final int width;
	private final boolean editable;
	private final boolean progressDetail;
	private final Method getter;
	private final Method setter;
	private final Class<?> type;

	MessageTableColumn(String caption, int width, boolean editable, boolean progressDetail, String getterName, String setterName, Class<?> type) {
		this.caption = caption;
		this.width = width;
		this.editable = editable;
		this.progressDetail = progressDetail;
		this.type = type;

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
	public boolean isProgressDetail() {
		return progressDetail;
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

	private static final Map<String, MessageTableColumn> captionToEnumMap;
	static {
		captionToEnumMap = Maps.newHashMap();
		Arrays.stream(values()).forEach(column -> captionToEnumMap.put(column.caption, column));
	}
	public static MessageTableColumn getByCaption(String caption) {
		return captionToEnumMap.get(caption);
	}

}
