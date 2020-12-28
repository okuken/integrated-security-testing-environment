package okuken.iste.view.chain;

import java.util.Arrays;
import java.util.List;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;
import okuken.iste.util.RegexUtil;
import okuken.iste.util.UiUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTablePanel;

public class ChainDefNodeRequestParamsPanel extends SimpleTablePanel<MessageChainNodeReqpDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = MessageChainNodeReqpDto.class;
	private static final int PARAM_TYPE = 0, PARAM_NAME = 1, SOURCE_TYPE = 2, SOURCE_NAME = 3;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(PARAM_TYPE,  "Type",         100, true, "getParamType",  "setParamType",  RequestParameterType.class, DTO_CLASS),
		new ColumnDef(PARAM_NAME,  "Name / Regex", 200, true, "getParamName",  "setParamName",  String.class, DTO_CLASS),
		new ColumnDef(SOURCE_TYPE, "Source type",  100, true, "getSourceType", "setSourceType", SourceType.class, DTO_CLASS),
		new ColumnDef(SOURCE_NAME, "Source name",  200, true, "getSourceName", "setSourceName", String.class, DTO_CLASS));

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.CHAIN_DEF_TABLE_TITLE_REQUEST_MANIPULATION;
	}

	@Override
	protected List<MessageChainNodeReqpDto> loadRowDtos() {
		return null; // because load(add) by parent panel
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
		setupParamTypeColumn(table);
		setupSourceTypeColumn(table);
	}

	@Override
	protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, MessageChainNodeReqpDto dto) {
		switch (columnIndex) {
			case PARAM_TYPE:
//				tableModel.setValueAt("", rowIndex, PARAM_NAME);
				break;
			case PARAM_NAME:
				if(dto.getParamType() == RequestParameterType.REGEX && !dto.getParamName().isEmpty()) {
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
	protected void afterAddRow(MessageChainNodeReqpDto dto) {
	}

	@Override
	protected void afterRemoveRow(MessageChainNodeReqpDto dto) {
	}

	@Override
	protected MessageChainNodeReqpDto createRowDto() {
		var dto = new MessageChainNodeReqpDto();
		dto.setParamType(RequestParameterType.COOKIE);
		dto.setSourceType(SourceType.VAR);
		return dto;
	}


	private void setupParamTypeColumn(JTable table) {
		var comboBox = new JComboBox<RequestParameterType>();
		Arrays.stream(RequestParameterType.values()).filter(RequestParameterType::isAppliable).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(PARAM_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}
	private void setupSourceTypeColumn(JTable table) {
		var comboBox = new JComboBox<SourceType>();
		Arrays.stream(SourceType.values()).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(SOURCE_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}

}
