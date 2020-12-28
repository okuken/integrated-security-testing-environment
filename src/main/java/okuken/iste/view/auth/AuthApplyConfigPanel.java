package okuken.iste.view.auth;

import java.util.Arrays;
import java.util.List;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthApplyConfigDto;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.RegexUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTablePanel;

public class AuthApplyConfigPanel extends SimpleTablePanel<AuthApplyConfigDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = AuthApplyConfigDto.class;
	private static final int PARAM_TYPE = 0, PARAM_NAME = 1, VAR_NAME = 2;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(PARAM_TYPE, "Request param type",         120, true, "getParamType", "setParamType",  RequestParameterType.class, DTO_CLASS),
		new ColumnDef(PARAM_NAME, "Request param name / Regex", 200, true, "getParamName", "setParamName",  String.class, DTO_CLASS),
		new ColumnDef(VAR_NAME,   "Source var name",            200, true, "getVarName",   "setVarName",    String.class, DTO_CLASS));

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.AUTH_CONFIG_TABLE_TITLE_APPLY_CONFIG;
	}

	@Override
	protected List<AuthApplyConfigDto> loadRowDtos() {
		return ConfigLogic.getInstance().getAuthConfig().getAuthApplyConfigDtos(); //[CAUTION] edit cache directly
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
		setupParamTypeColumn(table);
	}

	@Override
	protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, AuthApplyConfigDto dto) {
		switch (columnIndex) {
		case PARAM_NAME:
			if(dto.getParamType() == RequestParameterType.REGEX && !dto.getParamName().isEmpty()) {
				var errMsg = RegexUtil.judgeHasJustOneGroupAndReturnErrorMsg(dto.getParamName());
				if(errMsg != null) {
					UiUtil.showMessage(errMsg, table); // but save
				}
			}
			break;
		default:
		}

		//TODO: validation (empty is error, ...

		Controller.getInstance().saveAuthApplyConfig(dto);
	}

	@Override
	protected void afterAddRow(AuthApplyConfigDto dto) {
		Controller.getInstance().saveAuthApplyConfig(dto);
	}

	@Override
	protected void afterRemoveRow(AuthApplyConfigDto dto) {
		Controller.getInstance().deleteAuthApplyConfigs(Arrays.asList(dto));
	}

	@Override
	protected AuthApplyConfigDto createRowDto() {
		var dto = new AuthApplyConfigDto();
		dto.setAuthConfigId(ConfigLogic.getInstance().getAuthConfig().getId());
		dto.setParamType(RequestParameterType.COOKIE);
		dto.setParamName("");
		dto.setVarName("");
		return dto;
	}


	private void setupParamTypeColumn(JTable table) {
		var comboBox = new JComboBox<RequestParameterType>();
		Arrays.stream(RequestParameterType.values()).filter(RequestParameterType::isAppliable).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(PARAM_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}

}
