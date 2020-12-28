package okuken.iste.dto;

import java.net.URL;
import java.util.List;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.logic.MemoLogic;
import okuken.iste.logic.MessageLogic;
import okuken.iste.logic.RepeaterLogic;
import okuken.iste.util.MessageUtil;

public class MessageDto {

	private Integer id;

	private String name;
	private String remark;
	private SecurityTestingProgress progress;
	private String progressMemo;

	// personal items...??
	private String authMatrix;
	private String priority;
	private String progressTechnical;
	private String progressLogical;
	private String progressAuthentication;
	private String progressAuthorizationFeature;
	private String progressAuthorizationResource;
	private String progressCsrf;

	private Integer memoId;
	private String memo;
	private boolean memoChanged;

	private String method;
	private URL url;
	private Integer params;
	private Short status;
	private Integer length;
	private String mimeType;
	private String cookies;

	private List<MessageRequestParamDto> messageParamList;

	private List<MessageCookieDto> messageCookieList;
	private List<MessageResponseParamDto> responseJson;

	private Integer messageRawId;
	private IHttpRequestResponse message;
	private IRequestInfo requestInfo;
	private IResponseInfo responseInfo;

	private IHttpRequestResponse repeatMasterMessage;

	private List<MessageRepeatDto> repeatList;

	public String getProtocol() {
		if(url == null) {return null;}
		return url.getProtocol();
	}
	public String getHost() {
		if(url == null) {return null;}
		return url.getHost();
	}
	public Integer getPort() {
		if(url == null) {return null;}
		return url.getPort() != -1 ? url.getPort() : null;
	}
	public Integer getPortIfNotDefault() {
		if(url == null) {return null;}
		return url.getPort() != url.getDefaultPort() ? url.getPort() : null; 
	}
	public String getPortIfNotDefaultStr() {
		Integer port = getPortIfNotDefault();
		return port != null ? Integer.toString(port) : "";
	}
	public String getPath() {
		if(url == null) {return null;}
		return url.getPath();
	}
	public String getQuery() {
		if(url == null) {return null;}
		return url.getQuery();
	}
	/**
	 * not include default port.
	 */
	public String getUrlShort() {
		if(url == null) {return null;}
		return String.format("%s://%s%s", url.getProtocol(), createShortAuthority(url), url.getFile());
	}
	/**
	 * not include default port and GET parameters.
	 */
	public String getUrlShortest() {
		if(url == null) {return null;}
		return String.format("%s://%s%s", url.getProtocol(), createShortAuthority(url), url.getPath());
	}
	private String createShortAuthority(URL url) {
		String authority = url.getAuthority();
		if(url.getPort() == url.getDefaultPort()) {
			authority = authority.substring(0, authority.indexOf(":"));
		}
		return authority;
	}


	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	public SecurityTestingProgress getProgress() {
		return progress;
	}
	public void setProgress(SecurityTestingProgress progress) {
		this.progress = progress;
	}
	public String getProgressMemo() {
		return progressMemo;
	}
	public void setProgressMemo(String progressMemo) {
		this.progressMemo = progressMemo;
	}

	public String getAuthMatrix() {
		return authMatrix;
	}
	public void setAuthMatrix(String authMatrix) {
		this.authMatrix = authMatrix;
	}
	public String getPriority() {
		return priority;
	}
	public void setPriority(String priority) {
		this.priority = priority;
	}
	public String getProgressTechnical() {
		return progressTechnical;
	}
	public void setProgressTechnical(String progressTechnical) {
		this.progressTechnical = progressTechnical;
	}
	public String getProgressLogical() {
		return progressLogical;
	}
	public void setProgressLogical(String progressLogic) {
		this.progressLogical = progressLogic;
	}
	public String getProgressAuthentication() {
		return progressAuthentication;
	}
	public void setProgressAuthentication(String progressAuthentication) {
		this.progressAuthentication = progressAuthentication;
	}
	public String getProgressAuthorizationFeature() {
		return progressAuthorizationFeature;
	}
	public void setProgressAuthorizationFeature(String progressAuthorizationFeature) {
		this.progressAuthorizationFeature = progressAuthorizationFeature;
	}
	public String getProgressAuthorizationResource() {
		return progressAuthorizationResource;
	}
	public void setProgressAuthorizationResource(String progressAuthorizationResource) {
		this.progressAuthorizationResource = progressAuthorizationResource;
	}
	public String getProgressCsrf() {
		return progressCsrf;
	}
	public void setProgressCsrf(String progressCsrf) {
		this.progressCsrf = progressCsrf;
	}

	public Integer getMemoId() {
		if (memoId == null) {
			MemoLogic.getInstance().loadMessageMemo(this);
		}
		return memoId;
	}
	public Integer getMemoIdWithoutLoad() {
		return memoId;
	}
	public void setMemoId(Integer memoId) {
		this.memoId = memoId;
	}
	public String getMemo() {
		if (memoId == null) {
			MemoLogic.getInstance().loadMessageMemo(this);
		}
		return memo;
	}
	public String getMemoWithoutLoad() {
		return memo;
	}
	public void setMemo(String memo) {
		this.memo = memo;
	}
	public boolean isMemoChanged() {
		return memoChanged;
	}
	public void setMemoChanged(boolean memoChanged) {
		this.memoChanged = memoChanged;
	}


	public String getMethod() {
		return method;
	}
	public void setMethod(String method) {
		this.method = method;
	}
	public URL getUrl() {
		return url;
	}
	public void setUrl(URL url) {
		this.url = url;
	}
	public Integer getParams() {
		return params;
	}
	public String getParamsStr() {
		return Integer.toString(getParams());
	}
	public void setParams(Integer params) {
		this.params = params;
	}
	public Short getStatus() {
		return status;
	}
	public String getStatusStr() {
		return getStatus() != null ? Short.toString(getStatus()) : "";
	}
	public void setStatus(Short status) {
		this.status = status;
	}
	public Integer getLength() {
		return length;
	}
	public String getLengthStr() {
		return getLength() != null ? Integer.toString(getLength()) : "";
	}
	public void setLength(Integer length) {
		this.length = length;
	}
	public String getMimeType() {
		return mimeType;
	}
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}
	public String getCookies() {
		return cookies;
	}
	public void setCookies(String cookies) {
		this.cookies = cookies;
	}
	public List<MessageRequestParamDto> getMessageParamList() {
		if(messageParamList == null) {
			MessageLogic.getInstance().loadMessageDetail(this);
		}
		return messageParamList;
	}
	public void setMessageParamList(List<MessageRequestParamDto> messageParamList) {
		this.messageParamList = messageParamList;
	}
	public List<MessageCookieDto> getMessageCookieList() {
		if(messageCookieList == null) {
			MessageLogic.getInstance().loadMessageDetail(this);
		}
		return messageCookieList;
	}
	public void setMessageCookieList(List<MessageCookieDto> messageCookieList) {
		this.messageCookieList = messageCookieList;
	}
	public List<MessageResponseParamDto> getResponseJson() {
		if(responseJson == null && getMessage().getResponse() != null) {
			responseJson = MessageUtil.convertJsonResponseToDto(getMessage().getResponse(), getResponseInfo());
		}
		return responseJson;
	}
	public void setResponseJson(List<MessageResponseParamDto> responseJson) {
		this.responseJson = responseJson;
	}
	public Integer getMessageRawId() {
		return messageRawId;
	}
	public void setMessageRawId(Integer messageRawId) {
		this.messageRawId = messageRawId;
	}
	public IHttpRequestResponse getMessage() {
		if(message == null) {
			MessageLogic.getInstance().loadMessageDetail(this);
		}
		return message;
	}
	public void setMessage(IHttpRequestResponse message) {
		this.message = message;
	}
	public IRequestInfo getRequestInfo() {
		return requestInfo;
	}
	public void setRequestInfo(IRequestInfo requestInfo) {
		this.requestInfo = requestInfo;
	}
	public IResponseInfo getResponseInfo() {
		return responseInfo;
	}
	public void setResponseInfo(IResponseInfo responseInfo) {
		this.responseInfo = responseInfo;
	}
	public IHttpRequestResponse getRepeatMasterMessage() {
		if(repeatMasterMessage == null) {
			MessageLogic.getInstance().loadRepeatMaster(this);
		}
		return repeatMasterMessage;
	}
	public void setRepeatMasterMessage(IHttpRequestResponse repeatMasterMessage) {
		this.repeatMasterMessage = repeatMasterMessage;
	}

	public List<MessageRepeatDto> getRepeatList() {
		if(repeatList == null) {
			repeatList = RepeaterLogic.getInstance().loadHistory(getId());
		}
		return repeatList;
	}
	public void setRepeatList(List<MessageRepeatDto> repeatList) {
		this.repeatList = repeatList;
	}
	public void addRepeat(MessageRepeatDto repeatDto) {
		if(repeatList == null) {
			repeatList = Lists.newArrayList();
		}
		repeatList.add(repeatDto);
	}

	@Override
	public String toString() {
		return String.format("%s [%s]", name, getUrlShort());
	}

}