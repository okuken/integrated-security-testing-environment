package okuken.iste.view.common;

import java.util.List;
import java.util.stream.IntStream;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.enums.ExtractType;
import okuken.iste.util.MessageUtil;
import okuken.iste.util.RegexUtil;
import okuken.iste.util.UiUtil;

public abstract class SimpleTableExtractPanel<T> extends SimpleTablePanel<T> {

	private static final long serialVersionUID = 1L;

	@Override
	protected List<T> loadRowDtos() {
		return null;
	}

	@Override
	protected void afterInit(JTable table, DefaultTableModel tableModel) {
	}

	@Override
	protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, T dto) {
		if(!getExtractListenerColumns().contains(columnIndex)) {
			return;
		}

		if(isExtractRow(dto)) {
			var errMsg = validateExtractString(dto);
			if(errMsg != null) {
				UiUtil.showMessage(errMsg, this);
				setExtractResult(Captions.MESSAGE_EXTRACT_ERROR, rowIndex);
				return;
			}
		}
		refreshExtractResult(dto, rowIndex);
	}

	@Override
	protected void afterAddRow(T dto) {
		refreshExtractResult(dto, dtos.indexOf(dto));
	}

	@Override
	protected void afterRemoveRow(T dto) {
	}

	public void refreshAllExtractResult() {
		IntStream.range(0, dtos.size()).forEach(i -> {
			refreshExtractResult(dtos.get(i), i);
		});
	}

	private void refreshExtractResult(T dto, int row) {
		setExtractResult(calcExtractResult(dto, row), row);
	}
	private void setExtractResult(String extractResult, int row) {
		setValueAt(extractResult, row, getExtractResultColumn());
	}
	private String calcExtractResult(T dto, int row) {
		if(!isExtractRow(dto)) {
			return "-";
		}
		var extractString = getExtractString(dto);

		if(StringUtils.isEmpty(extractString)) {
			return "-";
		}

		var targetStr = getTestTarget(dto);
		if(targetStr == null) {
			return "";
		}

		switch (getExtractType(dto)) {
		case REGEX:
			return RegexUtil.extractOneGroup(targetStr, extractString);
		case HTML_TAG:
			return MessageUtil.extractResponseHtmlTagValue(targetStr, extractString);
		default:
			throw new IllegalArgumentException(getExtractType(dto).toString());
		}
	}

	private String validateExtractString(T dto) {
		var extractString = getExtractString(dto);
		if(StringUtils.isEmpty(extractString)) {
			return null;
		}

		switch (getExtractType(dto)) {
		case REGEX:
			return RegexUtil.judgeHasJustOneGroupAndReturnErrorMsg(extractString);
		case HTML_TAG:
			return MessageUtil.judgeIsValidExtractHtmlTagSetting(extractString) ? null : Captions.MESSAGE_INPUT_INVALID_EXTRACT_HTML_TAG;
		default:
			throw new IllegalArgumentException(getExtractType(dto).toString());
		}
	}

	abstract protected List<Integer> getExtractListenerColumns();
	abstract protected int getExtractResultColumn();
	abstract protected boolean isExtractRow(T dto);
	abstract protected ExtractType getExtractType(T dto);
	abstract protected String getExtractString(T dto);
	abstract protected String getTestTarget(T dto);

}
