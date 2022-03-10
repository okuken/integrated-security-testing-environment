package okuken.iste.view.chain;

import java.util.Arrays;
import java.util.List;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageChainPresetVarDto;
import okuken.iste.util.UiUtil;
import okuken.iste.view.common.ColumnDef;
import okuken.iste.view.common.SimpleTablePanel;

public class ChainDefPresetVarsPanel extends SimpleTablePanel<MessageChainPresetVarDto> {

	private static final long serialVersionUID = 1L;

	private static final Class<?> DTO_CLASS = MessageChainPresetVarDto.class;
	private static final int NAME = 0, VALUE = 1;
	private static final List<ColumnDef> columns = Arrays.asList(
		new ColumnDef(NAME,  "Name", 100, true, "getName",  "setName",  String.class, DTO_CLASS),
		new ColumnDef(VALUE, "Value", 200, true, "getValue",  "setValue",  String.class, DTO_CLASS));

	private ChainDefPanel parentChainDefPanel;

	public ChainDefPresetVarsPanel(ChainDefPanel parentChainDefPanel) {
		super();
		this.parentChainDefPanel = parentChainDefPanel;
	}

	@Override
	protected List<ColumnDef> getColumnDefs() {
		return columns;
	}

	@Override
	protected String getTableCaption() {
		return Captions.CHAIN_DEF_TABLE_TITLE_PRESET_VARS;
	}

	@Override
	protected List<MessageChainPresetVarDto> loadRowDtos() {
		return parentChainDefPanel.getLoadedMessageChainDto().getPresetVars();
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
	}

	@Override
	protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, MessageChainPresetVarDto dto) {
		switch (columnIndex) {
			case NAME:
				if(StringUtils.isEmpty(dto.getName())) {
					UiUtil.showMessage("Name is required.", table);
					return;
				}
				break;
			case VALUE:
				break;
			default:
				return;
		}
	}

	@Override
	protected void afterAddRow(MessageChainPresetVarDto dto) {
	}

	@Override
	protected void afterRemoveRow(MessageChainPresetVarDto dto) {
	}

	@Override
	protected MessageChainPresetVarDto createRowDto() {
		var ret = new MessageChainPresetVarDto();
		ret.setName("var" + (getRows().size() + 1));
		return ret;
	}

}
