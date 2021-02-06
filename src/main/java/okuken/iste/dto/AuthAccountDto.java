package okuken.iste.dto;

import java.util.Optional;

import okuken.iste.consts.Sizes;
import okuken.iste.util.UiUtil;

public class AuthAccountDto {

	private Integer id;

	private String field01;
	private String field02;
	private String field03;
	private String field04;
	private String field05;
	private String remark;

	private String sessionId;

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public String getField01() {
		return field01;
	}
	public void setField01(String field01) {
		this.field01 = field01;
	}
	public String getField02() {
		return field02;
	}
	public void setField02(String field02) {
		this.field02 = field02;
	}
	public String getField03() {
		return field03;
	}
	public void setField03(String field03) {
		this.field03 = field03;
	}
	public String getField04() {
		return field04;
	}
	public void setField04(String field04) {
		this.field04 = field04;
	}
	public String getField05() {
		return field05;
	}
	public void setField05(String field05) {
		this.field05 = field05;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	public String getSessionId() {
		return sessionId;
	}
	public void setSessionId(String sessionId) {
		this.sessionId = sessionId;
	}

	public String getSessionIdForDisplay() {
		return UiUtil.omitString(getSessionId(), Sizes.OMIT_STRING_SIZE_AUTH_SESSION_VALUE);
	}

	public String getField(String fieldId) {
		switch (Integer.parseInt(fieldId.toUpperCase().replace("FIELD", "").trim())) {
		case 1: return field01;
		case 2: return field02;
		case 3: return field03;
		case 4: return field04;
		case 5: return field05;
		default: throw new IllegalArgumentException(fieldId);
		}
	}

	@Override
	public String toString() {
		return String.format("%s - %s", 
				UiUtil.omitString(Optional.ofNullable(field01).orElse(""), Sizes.OMIT_STRING_SIZE_AUTH_USERID),
				UiUtil.omitStringTail(Optional.ofNullable(remark).orElse(""), Sizes.OMIT_STRING_SIZE_AUTH_REMARK));
	}
}
