package okuken.iste.view.chain;

import java.util.Arrays;
import java.util.List;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageChainNodeRespDto;
import okuken.iste.enums.ExtractType;
import okuken.iste.enums.ResponseParameterType;
import okuken.iste.util.MessageUtil;
import okuken.iste.util.RegexUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTableExtractPanel;

public class ChainDefNodeResponseParamsPanel extends SimpleTableExtractPanel<MessageChainNodeRespDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = MessageChainNodeRespDto.class;
	private static final int PARAM_TYPE = 0, PARAM_NAME = 1, SOURCE_NAME = 2, EXTRACT_RESULT = 3;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(PARAM_TYPE,  "Type",                            75, true, "getParamType",  "setParamType",  ResponseParameterType.class, DTO_CLASS),
		new ColumnDef(PARAM_NAME,  "Name / Regex / Selector;attr",   275, true, "getParamName",  "setParamName",  String.class, DTO_CLASS),
		new ColumnDef(SOURCE_NAME, "Var name",                       150, true, "getVarName",    "setVarName",    String.class, DTO_CLASS),
		new ColumnDef(EXTRACT_RESULT,"(Extract result)",             100));

	private static final List<Integer> EXTRACT_LISTENER_COLUMNS = Lists.newArrayList(PARAM_TYPE, PARAM_NAME);

	private ChainDefNodePanel parentChainDefNodePanel;

	public ChainDefNodeResponseParamsPanel(ChainDefNodePanel parent) {
		super();
		this.parentChainDefNodePanel = parent;
	}

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.CHAIN_DEF_TABLE_TITLE_RESPONSE_MEMORIZATION;
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
		super.afterInit(table, tableModel);
		setupParamTypeColumn(table);
	}

	@Override
	protected MessageChainNodeRespDto createRowDto() {
		var dto = new MessageChainNodeRespDto();
		dto.setParamType(ResponseParameterType.REGEX);
		return dto;
	}


	private void setupParamTypeColumn(JTable table) {
		var comboBox = new JComboBox<ResponseParameterType>();
		Arrays.stream(ResponseParameterType.values()).filter(ResponseParameterType::isExtractable).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(PARAM_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}


	@Override
	protected List<Integer> getExtractListenerColumns() {
		return EXTRACT_LISTENER_COLUMNS;
	}
	@Override
	protected int getExtractResultColumn() {
		return EXTRACT_RESULT;
	}
	@Override
	protected boolean isExtractRow(MessageChainNodeRespDto dto) {
		return getExtractType(dto) != null;
	}
	@Override
	protected ExtractType getExtractType(MessageChainNodeRespDto dto) {
		return dto.getParamType().getExtractType();
	}
	@Override
	protected String getExtractString(MessageChainNodeRespDto dto) {
		return dto.getParamName();
	}
	@Override
	protected String getTestTarget(MessageChainNodeRespDto dto) {
		switch (getExtractType(dto)) {
		case REGEX:
			return RegexUtil.convertToStringForRegex(parentChainDefNodePanel.getResponse());
		case HTML_TAG:
			return MessageUtil.convertToResponseHtmlString(parentChainDefNodePanel.getResponse()).orElse("");
		default:
			return null;
		}
	}

}
