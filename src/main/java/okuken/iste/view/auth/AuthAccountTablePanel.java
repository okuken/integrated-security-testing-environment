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
	private static final int FIELD_01 = 0, FIELD_02 = 1, FIELD_03 = 2, FIELD_04 = 3, FIELD_05 = 4, REMARK = 5;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(FIELD_01, "Field 1 (ID)", 100, true, "getField01",  "setField01",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_02, "Field 2 (PW)", 100, true, "getField02",  "setField02",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_03, "Field 3",      10,  true, "getField03",  "setField03",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_04, "Field 4",      10,  true, "getField04",  "setField04",  String.class, DTO_CLASS),
		new ColumnDef(FIELD_05, "Field 5",      10,  true, "getField05",  "setField05",  String.class, DTO_CLASS),
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
		dto.setSessionId(null);
		Controller.getInstance().saveAuthAccount(dto, columnIndex == REMARK);
	}

	@Override
	protected void afterAddRow(AuthAccountDto dto) {
		Controller.getInstance().saveAuthAccount(dto, false);
	}

	@Override
	protected void afterRemoveRow(AuthAccountDto dto) {
		Controller.getInstance().deleteAuthAccounts(Arrays.asList(dto));
	}

	@Override
	protected AuthAccountDto createRowDto() {
		return new AuthAccountDto();
	}

}
