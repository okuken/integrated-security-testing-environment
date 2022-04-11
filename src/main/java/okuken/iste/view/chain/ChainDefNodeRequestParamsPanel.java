package okuken.iste.view.chain;

import java.util.Arrays;
import java.util.List;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.enums.EncodeType;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;
import okuken.iste.util.RegexUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTableRegexPanel;

public class ChainDefNodeRequestParamsPanel extends SimpleTableRegexPanel<MessageChainNodeReqpDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = MessageChainNodeReqpDto.class;
	private static final int PARAM_TYPE = 0, PARAM_NAME = 1, SOURCE_TYPE = 2, SOURCE_NAME = 3, ENCODE = 4, REGEX_RESULT = 5;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(PARAM_TYPE,  "Type",            75, true, "getParamType",  "setParamType",  RequestParameterType.class, DTO_CLASS),
		new ColumnDef(PARAM_NAME,  "Name / Regex",   200, true, "getParamName",  "setParamName",  String.class, DTO_CLASS),
		new ColumnDef(SOURCE_TYPE, "Source type",     75, true, "getSourceType", "setSourceType", SourceType.class, DTO_CLASS),
		new ColumnDef(SOURCE_NAME, "Source name",     75, true, "getSourceName", "setSourceName", String.class, DTO_CLASS),
		new ColumnDef(ENCODE,      "Encode",          75, true, "getEncode",     "setEncode",     EncodeType.class, DTO_CLASS),
		new ColumnDef(REGEX_RESULT,"(Regex result)", 100));

	private static final List<Integer> REGEX_LISTENER_COLUMNS = Lists.newArrayList(PARAM_TYPE, PARAM_NAME);

	private ChainDefNodePanel parentChainDefNodePanel;

	public ChainDefNodeRequestParamsPanel(ChainDefNodePanel parentChainDefNodePanel) {
		super();
		this.parentChainDefNodePanel = parentChainDefNodePanel;
		afterInit();
	}

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.CHAIN_DEF_TABLE_TITLE_REQUEST_MANIPULATION;
	}

	private void afterInit() {
		setupParamTypeColumn(table);
		setupSourceTypeColumn(table);
		setupEncodeColumn(table);
	}

	@Override
	protected MessageChainNodeReqpDto createRowDto() {
		var dto = new MessageChainNodeReqpDto();
		dto.setParamType(RequestParameterType.COOKIE);
		dto.setSourceType(SourceType.VAR);
		dto.setEncode(EncodeType.NONE);
		return dto;
	}


	private void setupParamTypeColumn(JTable table) {
		var comboBox = new JComboBox<RequestParameterType>();
		Arrays.stream(RequestParameterType.values()).filter(RequestParameterType::isAppliable).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(PARAM_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}
	private void setupSourceTypeColumn(JTable table) {
		var comboBox = new JComboBox<SourceType>();
		Arrays.stream(SourceType.values())
			.filter(type -> !type.isAuthOnly() || parentChainDefNodePanel.getParentChainDefPanel().judgeIsAuthChain())
			.forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(SOURCE_TYPE).setCellEditor(new DefaultCellEditor(comboBox));
	}
	private void setupEncodeColumn(JTable table) {
		var comboBox = new JComboBox<EncodeType>();
		Arrays.stream(EncodeType.values()).forEach(item -> comboBox.addItem(item));
		table.getColumnModel().getColumn(ENCODE).setCellEditor(new DefaultCellEditor(comboBox));
	}


	@Override
	protected List<Integer> getRegexListenerColumns() {
		return REGEX_LISTENER_COLUMNS;
	}
	@Override
	protected int getRegexResultColumn() {
		return REGEX_RESULT;
	}
	@Override
	protected boolean isRegexRow(MessageChainNodeReqpDto dto) {
		return dto.getParamType() == RequestParameterType.REGEX;
	}
	@Override
	protected String getRegex(MessageChainNodeReqpDto dto) {
		return dto.getParamName();
	}
	@Override
	protected String getTestTarget() {
		return RegexUtil.convertToStringForRegex(parentChainDefNodePanel.getRequest());
	}

}
