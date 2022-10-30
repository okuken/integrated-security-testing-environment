package okuken.iste.dto;

import java.util.Date;

import okuken.iste.logic.MessageLogic;

public class MessageRepeatRedirectDto {

	private Integer id;

	private Date sendDate;
	private Short status;
	private Integer length;
	private Integer time;

	private Integer messageRawId;
	private HttpRequestResponseDto message;

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
	public HttpRequestResponseDto getMessage() {
		if (message == null) {
			message = MessageLogic.getInstance().loadMessageDetail(messageRawId);
		}
		return message;
	}
	public void setMessage(HttpRequestResponseDto message) {
		this.message = message;
	}

}
