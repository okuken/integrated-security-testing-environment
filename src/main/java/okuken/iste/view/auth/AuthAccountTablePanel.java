package okuken.iste.view.auth;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTablePanel;

import java.util.Arrays;
import java.util.List;

public class AuthAccountTablePanel extends SimpleTablePanel<AuthAccountDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = AuthAccountDto.class;
	private static final int FIELD_01 = 0, FIELD_02 = 1, FIELD_03 = 2, FIELD_04 = 3, FIELD_05 = 4,
	                         FIELD_06 = 5, FIELD_07 = 6, FIELD_08 = 7, FIELD_09 = 8, FIELD_10 = 9, REMARK = 10;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(FIELD_01, "Field 1 (ID)", 100, true, "getField01",  "setField01",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_02, "Field 2 (PW)", 100, true, "getField02",  "setField02",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_03, "Field 3",      10,  true, "getField03",  "setField03",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_04, "Field 4",      10,  true, "getField04",  "setField04",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_05, "Field 5",      10,  true, "getField05",  "setField05",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_06, "Field 6",      10,  true, "getField06",  "setField06",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_07, "Field 7",      10,  true, "getField07",  "setField07",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_08, "Field 8",      10,  true, "getField08",  "setField08",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_09, "Field 9",      10,  true, "getField09",  "setField09",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_10, "Field 10",     10,  true, "getField10",  "setField10",  String.class, DTO_CLASS),
		new ColumnDef(REMARK,   "Remark",       300, true, "getRemark",   "setRemark",   String.class, DTO_CLASS));

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.AUTH_CONFIG_TABLE_TITLE_ACCOUNTS;
	}

	@Override
	protected List<AuthAccountDto> loadRowDtos() {
		return Controller.getInstance().getAuthAccounts();
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
	}

	@Override
	protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, AuthAccountDto dto) {
		var keepOldSessionId = (columnIndex == REMARK);
		if(!keepOldSessionId) {
			dto.setSessionIds(null);
		}
		Controller.getInstance().saveAuthAccount(dto, keepOldSessionId);
	}

	@Override
	protected void afterAddRow(AuthAccountDto dto) {
		Controller.getInstance().saveNewAuthAccount(dto, false, getRows());
	}

	@Override
	protected void afterRemoveRow(AuthAccountDto dto) {
	}

	@Override
	protected void afterRemoveRows(List<AuthAccountDto> dtos) {
		Controller.getInstance().deleteAuthAccounts(dtos, getRows());
	}
	@Override
	protected void afterUpRows(List<AuthAccountDto> dtos) {
		Controller.getInstance().saveAuthAccountsOrder(getRows());
	}
	@Override
	protected void afterDownRows(List<AuthAccountDto> dtos) {
		Controller.getInstance().saveAuthAccountsOrder(getRows());
	}

	@Override
	protected AuthAccountDto createRowDto() {
		return new AuthAccountDto();
	}

}
