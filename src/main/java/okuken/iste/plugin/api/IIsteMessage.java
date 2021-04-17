package okuken.iste.plugin.api;

public interface IIsteMessage {

	String getProtocol();
	Integer getPort();
	String getHost();
	byte[] getRequest();
	byte[] getResponse();

	String getUrl();
	String getUrlWithoutQuery();
	String getMethod();
	String getPath();
	String getQuery();
	Integer getParamCount();
	Short getStatus();
	Integer getLength();
	String getMimeType();
	String getCookies();

	String getName();
	String getRemark();
	String getPriority();
	String getProgress();
	String getProgressNotes();
	String getNotes();

}
