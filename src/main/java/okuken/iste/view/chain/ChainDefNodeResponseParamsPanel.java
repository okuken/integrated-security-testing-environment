package okuken.iste.view.chain;

import java.util.Arrays;
import java.util.List;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageChainNodeRespDto;
import okuken.iste.enums.ResponseParameterType;
import okuken.iste.util.RegexUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTablePanel;

public class ChainDefNodeResponseParamsPanel extends SimpleTablePanel<MessageChainNodeRespDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = MessageChainNodeRespDto.class;
	private static final int PARAM_TYPE = 0, PARAM_NAME = 1, SOURCE_NAME = 2;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(PARAM_TYPE,  "Type",         100, true, "getParamType",  "setParamType",  ResponseParameterType.class, DTO_CLASS),
		new ColumnDef(PARAM_NAME,  "Name / Regex", 200, true, "getParamName",  "setParamName",  String.class, DTO_CLASS),
		new ColumnDef(SOURCE_NAME, "Var name",     300, true, "getVarName",    "setVarName",    String.class, DTO_CLASS));

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.CHAIN_DEF_TABLE_TITLE_RESPONSE_MEMORIZATION;
	}

	@Override
	protected List<MessageChainNodeRespDto> loadRowDtos() {
		return null; // because load(add) by parent panel
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
		setupParamTypeColumn(table);
	}

	@Override
	protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, MessageChainNodeRespDto dto) {
		switch (columnIndex) {
			case PARAM_TYPE:
//				tableModel.setValueAt("", rowIndex, PARAM_NAME);
				break;
			case PARAM_NAME:
				if(dto.getParamType() == ResponseParameterType.REGEX && !dto.getParamName().isEmpty()) {
					var errMsg = RegexUtil.judgeHasJustOneGroupAndReturnErrorMsg(dto.getParamName());
					if(errMsg != null) {
						UiUtil.showMessage(errMsg, table);
					}
				}
				break;
			default:
				return;
		}
	}

	@Override
	protected void afterAddRow(MessageChainNodeRespDto dto) {
	}

	@Override
	protected void afterRemoveRow(MessageChainNodeRespDto dto) {
	}

	@Override
	protected MessageChainNodeRespDto createRowDto() {
		var dto = new MessageChainNodeRespDto();
		dto.setParamType(ResponseParameterType.COOKIE);
		return dto;
	}


	private void setupParamTypeColumn(JTable table) {
		var comboBox = new JComboBox<ResponseParameterType>();
		Arrays.stream(ResponseParameterType.values()).filter(ResponseParameterType::isExtractable).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(PARAM_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}

}
