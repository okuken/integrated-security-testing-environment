package okuken.iste.dto;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import com.google.common.base.Predicates;

import okuken.iste.consts.Sizes;
import okuken.iste.util.ReflectionUtil;
import okuken.iste.util.UiUtil;

public class AuthAccountDto {

	public static final String FIELD_GETTER_FORMAT = "getField%02d";
	public static final String FIELD_SETTER_FORMAT = "setField%02d";
	public static final int    FIELD_START_NUM     = 1;
	public static final int    FIELD_END_NUM       = 10;
	public static final String SESSIONID_GETTER_FORMAT = "getSessionId%02d";
	public static final String SESSIONID_SETTER_FORMAT = "setSessionId%02d";
	public static final int    SESSIONID_START_NUM     = 1;
	public static final int    SESSIONID_END_NUM       = 10;

	private Integer id;

	private String field01;
	private String field02;
	private String field03;
	private String field04;
	private String field05;
	private String field06;
	private String field07;
	private String field08;
	private String field09;
	private String field10;

	private String remark;

	private List<String> sessionIds;

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
	public String getField06() {
		return field06;
	}
	public void setField06(String field06) {
		this.field06 = field06;
	}
	public String getField07() {
		return field07;
	}
	public void setField07(String field07) {
		this.field07 = field07;
	}
	public String getField08() {
		return field08;
	}
	public void setField08(String field08) {
		this.field08 = field08;
	}
	public String getField09() {
		return field09;
	}
	public void setField09(String field09) {
		this.field09 = field09;
	}
	public String getField10() {
		return field10;
	}
	public void setField10(String field10) {
		this.field10 = field10;
	}
	public String getRemark() {
		return remark;
	}
	public void setRemark(String remark) {
		this.remark = remark;
	}
	public List<String> getSessionIds() {
		return sessionIds;
	}
	public void setSessionIds(List<String> sessionIds) {
		this.sessionIds = sessionIds;
	}

	public boolean isSessionIdsEmpty() {
		return sessionIds == null || sessionIds.isEmpty() || sessionIds.stream().allMatch(Objects::isNull);
	}

	public String getSessionIdForDisplay() {
		return isSessionIdsEmpty() ? "" : 
			UiUtil.omitString(sessionIds.stream().filter(Predicates.notNull()).findFirst().get(), Sizes.OMIT_STRING_SIZE_AUTH_SESSION_VALUE);
	}

	public String getUserId() {
		return field01;
	}

	public String getField(String fieldId) {
		return ReflectionUtil.getNumberedField(this, FIELD_GETTER_FORMAT,
				Integer.parseInt(fieldId.toUpperCase().replace("FIELD", "").trim()));
	}

	@Override
	public String toString() {
		return String.format("%s - %s", 
				UiUtil.omitString(Optional.ofNullable(getUserId()).orElse(""), Sizes.OMIT_STRING_SIZE_AUTH_USERID),
				UiUtil.omitStringTail(Optional.ofNullable(remark).orElse(""), Sizes.OMIT_STRING_SIZE_AUTH_REMARK));
	}
}
