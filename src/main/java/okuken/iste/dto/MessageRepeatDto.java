package okuken.iste.dto;

import java.util.Date;
import java.util.List;

import okuken.iste.logic.MessageLogic;

public class MessageRepeatDto {

	private Integer id;

	private Date sendDate;
	private String difference; //TODO: structure
	private String userId;

	private Short status;
	private Integer length;
	private Integer time;

	private String memo;

	private Integer messageRawId;
	private HttpRequestResponseDto message;

	private Integer orgMessageId;

	private boolean chainFlag;

	private List<MessageRepeatRedirectDto> messageRepeatRedirectDtos;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public Date getSendDate() {
		return sendDate;
	}
	public void setSendDate(Date sendDate) {
		this.sendDate = sendDate;
	}
	public String getDifference() {
		return difference;
	}
	public void setDifference(String difference) {
		this.difference = difference;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public Short getStatus() {
		return status;
	}
	public void setStatus(Short status) {
		this.status = status;
	}
	public Integer getLength() {
		return length;
	}
	public void setLength(Integer length) {
		this.length = length;
	}
	public Integer getTime() {
		return time;
	}
	public void setTime(Integer time) {
		this.time = time;
	}
	public String getMemo() {
		return memo;
	}
	public void setMemo(String memo) {
		this.memo = memo;
	}
	public Integer getMessageRawId() {
		return messageRawId;
	}
	public void setMessageRawId(Integer messageRawId) {
		this.messageRawId = messageRawId;
	}
	public HttpRequestResponseDto getMessage() {
		if (message == null) {
			message = MessageLogic.getInstance().loadMessageDetail(messageRawId);
		}
		return message;
	}
	public void setMessage(HttpRequestResponseDto message) {
		this.message = message;
	}
	public Integer getOrgMessageId() {
		return orgMessageId;
	}
	public void setOrgMessageId(Integer orgMessageId) {
		this.orgMessageId = orgMessageId;
	}
	public boolean isChainFlag() {
		return chainFlag;
	}
	public void setChainFlag(boolean chainFlag) {
		this.chainFlag = chainFlag;
	}

	public List<MessageRepeatRedirectDto> getMessageRepeatRedirectDtos() {
		return messageRepeatRedirectDtos;
	}
	public void setMessageRepeatRedirectDtos(List<MessageRepeatRedirectDto> messageRepeatRedirectDtos) {
		this.messageRepeatRedirectDtos = messageRepeatRedirectDtos;
	}

}
