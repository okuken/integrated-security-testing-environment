package okuken.iste.view.common;

import java.util.List;
import java.util.stream.IntStream;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.util.RegexUtil;
import okuken.iste.util.UiUtil;

public abstract class SimpleTableRegexPanel<T> extends SimpleTablePanel<T> {

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
		if(!getRegexListenerColumns().contains(columnIndex)) {
			return;
		}

		if(isRegexRow(dto) && !StringUtils.isEmpty(getRegex(dto))) {
			var errMsg = RegexUtil.judgeHasJustOneGroupAndReturnErrorMsg(getRegex(dto));
			if(errMsg != null) {
				UiUtil.showMessage(errMsg, this);
				setRegexResult(Captions.MESSAGE_REGEX_ERROR, rowIndex);
				return;
			}
		}
		refreshRegexResult(dto, rowIndex);
	}

	@Override
	protected void afterAddRow(T dto) {
		refreshRegexResult(dto, dtos.indexOf(dto));
	}

	@Override
	protected void afterRemoveRow(T dto) {
	}

	public void refreshAllRegexResult() {
		IntStream.range(0, dtos.size()).forEach(i -> {
			refreshRegexResult(dtos.get(i), i);
		});
	}

	private void refreshRegexResult(T dto, int row) {
		setRegexResult(calcRegexResult(dto, row), row);
	}
	private void setRegexResult(String regexResult, int row) {
		setValueAt(regexResult, row, getRegexResultColumn());
	}
	private String calcRegexResult(T dto, int row) {
		if(!isRegexRow(dto)) {
			return "-";
		}
		var regex = getRegex(dto);

		if(StringUtils.isEmpty(regex)) {
			return "-";
		}

		var targetStr = getTestTarget();
		if(targetStr == null) {
			return "";
		}

		return RegexUtil.extractOneGroup(targetStr, regex);
	}


	abstract protected List<Integer> getRegexListenerColumns();
	abstract protected int getRegexResultColumn();
	abstract protected boolean isRegexRow(T dto);
	abstract protected String getRegex(T dto);
	abstract protected String getTestTarget();

}
