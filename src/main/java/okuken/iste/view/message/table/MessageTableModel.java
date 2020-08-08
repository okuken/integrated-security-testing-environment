package okuken.iste.view.message.table;

import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.table.AbstractTableModel;

import com.google.common.collect.Lists;

import okuken.iste.dto.MessageDto;
import okuken.iste.logic.MessageLogic;

public class MessageTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;

	private static final MessageTableColumn[] COLUMNS = {
			MessageTableColumn.PROTOCOL,
			MessageTableColumn.HOST,
			MessageTableColumn.PORT,
			MessageTableColumn.METHOD,
			MessageTableColumn.PATH,
			MessageTableColumn.QUERY,
			MessageTableColumn.NAME,
			MessageTableColumn.REMARK,
			MessageTableColumn.AUTH,
			MessageTableColumn.PRIORITY,
			MessageTableColumn.PROGRESS_MEMO,
			MessageTableColumn.PROGRESS_TECHNICAL,
			MessageTableColumn.PROGRESS_LOGICAL,
			MessageTableColumn.PROGRESS_AUTHENTICATION,
			MessageTableColumn.PROGRESS_AUTH_FEATURE,
			MessageTableColumn.PROGRESS_AUTH_RESOURCE,
			MessageTableColumn.PROGRESS_CSRF,
			MessageTableColumn.PROGRESS,
			MessageTableColumn.PARAMS,
			MessageTableColumn.STATUS,
			MessageTableColumn.LENGTH,
			MessageTableColumn.MIME_TYPE,
			MessageTableColumn.COOKIES,
			MessageTableColumn.URL};

	private List<MessageDto> rows = Lists.newArrayList();

	public MessageTableModel() {
	}

	public void addRows(List<MessageDto> messageDtos) {
		if(messageDtos.isEmpty()) {
			return;
		}
		int beginIndex = rows.size();
		this.rows.addAll(messageDtos);
		fireTableRowsInserted(beginIndex, getRowCount() - 1);
	}

	public void insertRows(int rowIndex, List<MessageDto> messageDtos) {
		for(int i = 0; i < messageDtos.size(); i++) {
			this.rows.add(rowIndex + i, messageDtos.get(i));
		}
		fireTableRowsInserted(rowIndex, rowIndex + messageDtos.size() - 1);
	}

	public void removeRow(int rowIndex) {
		this.rows.remove(rowIndex);
		fireTableRowsDeleted(rowIndex, rowIndex);
	}

	public void clearRows() {
		int rowCount = getRowCount();
		if(rowCount > 0) {
			this.rows.clear();
			fireTableRowsDeleted(0, rowCount - 1);
		}
	}

	public List<MessageDto> getRows() {
		return rows;
	}

	public String getRowsAsTsv(int[] rows) {
		return Arrays.stream(rows).mapToObj(
				row -> IntStream.range(0, COLUMNS.length).mapToObj(
				column -> Optional.ofNullable(getValueAt(row, column)).orElse("").toString())
				.collect(Collectors.joining("\t")))
				.collect(Collectors.joining(System.lineSeparator()));
	}

	public MessageDto getRow(int rowIndex) {
		return rows.get(rowIndex);
	}

	@Override
	public int getRowCount() {
		return rows.size();
	}

	@Override
	public int getColumnCount() {
		return COLUMNS.length;
	}

	@Override
	public String getColumnName(int columnIndex) {
		return COLUMNS[columnIndex].getCaption();
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return COLUMNS[columnIndex].isEditable();
	}

	@Override
	public void setValueAt(Object val, int rowIndex, int columnIndex) {
		var column = COLUMNS[columnIndex];
		if(!column.isEditable()) {
			throw new IllegalArgumentException();
		}

		try {
			MessageDto dto = rows.get(rowIndex);
			if(val.equals(column.getGetter().invoke(dto))) { //case: no change
				return;
			}

			column.getSetter().invoke(dto, val);
			MessageLogic.getInstance().updateMessage(dto);

		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}

	public int getColumnIndex(MessageTableColumn column) {
		for(int i = 0; i < COLUMNS.length; i++) {
			if(column == COLUMNS[i]) {
				return i;
			}
		}
		throw new IllegalArgumentException();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return getColumnValue(rows.get(rowIndex), columnIndex);
	}
	private String getColumnValue(MessageDto row, int columnIndex) {
		try {
			var value = COLUMNS[columnIndex].getGetter().invoke(row);
			return value != null ? value.toString() : "";
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}