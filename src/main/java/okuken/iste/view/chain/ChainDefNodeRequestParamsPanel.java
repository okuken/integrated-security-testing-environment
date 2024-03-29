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
import okuken.iste.enums.ExtractType;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;
import okuken.iste.util.RegexUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTableExtractPanel;

public class ChainDefNodeRequestParamsPanel extends SimpleTableExtractPanel<MessageChainNodeReqpDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = MessageChainNodeReqpDto.class;
	private static final int PARAM_TYPE = 0, PARAM_NAME = 1, SOURCE_TYPE = 2, SOURCE_NAME = 3, ENCODE = 4, EXTRACT_RESULT = 5;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(PARAM_TYPE,  "Type",            75, true, "getParamType",  "setParamType",  RequestParameterType.class, DTO_CLASS),
		new ColumnDef(PARAM_NAME,  "Name / Regex",   200, true, "getParamName",  "setParamName",  String.class, DTO_CLASS),
		new ColumnDef(SOURCE_TYPE, "Source type",     75, true, "getSourceType", "setSourceType", SourceType.class, DTO_CLASS),
		new ColumnDef(SOURCE_NAME, "Source name",    105, true, "getSourceName", "setSourceName", String.class, DTO_CLASS),
		new ColumnDef(ENCODE,      "Encode",          45, true, "getEncode",     "setEncode",     EncodeType.class, DTO_CLASS),
		new ColumnDef(EXTRACT_RESULT,"(Extract result)",100));

	private static final List<Integer> EXTRACT_LISTENER_COLUMNS = Lists.newArrayList(PARAM_TYPE, PARAM_NAME);

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
		dto.setParamType(getInitialParamType());
		dto.setSourceType(SourceType.VAR);
		dto.setEncode(EncodeType.NONE);
		return dto;
	}
	private RequestParameterType getInitialParamType() {
		var parameters = parentChainDefNodePanel.getSelectedMessageDto().getRequestInfo().getParameters();
		if(parameters.stream().anyMatch(p -> p.getType() == RequestParameterType.URL.getBurpId())) {
			return RequestParameterType.URL;
		}
		if(parameters.stream().anyMatch(p -> p.getType() == RequestParameterType.BODY.getBurpId())) {
			return RequestParameterType.BODY;
		}
		return RequestParameterType.REGEX;
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
	protected List<Integer> getExtractListenerColumns() {
		return EXTRACT_LISTENER_COLUMNS;
	}
	@Override
	protected int getExtractResultColumn() {
		return EXTRACT_RESULT;
	}
	@Override
	protected boolean isExtractRow(MessageChainNodeReqpDto dto) {
		return getExtractType(dto) != null;
	}
	@Override
	protected ExtractType getExtractType(MessageChainNodeReqpDto dto) {
		return dto.getParamType().getExtractType();
	}
	@Override
	protected String getExtractString(MessageChainNodeReqpDto dto) {
		return dto.getParamName();
	}
	@Override
	protected String getTestTarget(MessageChainNodeReqpDto dto) {
		return RegexUtil.convertToStringForRegex(parentChainDefNodePanel.getRequest());
	}

}
