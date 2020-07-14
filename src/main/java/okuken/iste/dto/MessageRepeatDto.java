package okuken.iste.dto;

import java.util.Date;

import burp.IHttpRequestResponse;
import okuken.iste.logic.MessageLogic;

public class MessageRepeatDto {

	private Date sendDate;
	private String difference; //TODO: structure

	private Short status;
	private Integer length;
	private Integer time;

	private Integer messageRawId;
	private IHttpRequestResponse message;

	private Integer orgMessageId;

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
	public Integer getMessageRawId() {
		return messageRawId;
	}
	public void setMessageRawId(Integer messageRawId) {
		this.messageRawId = messageRawId;
	}
	public IHttpRequestResponse getMessage() {
		if (message == null) {
			message = MessageLogic.getInstance().loadMessageDetail(messageRawId);
		}
		return message;
	}
	public void setMessage(IHttpRequestResponse message) {
		this.message = message;
	}
	public Integer getOrgMessageId() {
		return orgMessageId;
	}
	public void setOrgMessageId(Integer orgMessageId) {
		this.orgMessageId = orgMessageId;
	}

}
