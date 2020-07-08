package okuken.iste.view.message.table;

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
			MessageTableColumn.NAME,
			MessageTableColumn.URL,
			MessageTableColumn.REMARK,
			MessageTableColumn.METHOD,
			MessageTableColumn.PARAMS,
			MessageTableColumn.STATUS,
			MessageTableColumn.LENGTH,
			MessageTableColumn.MIME_TYPE,
			MessageTableColumn.COOKIES};

	private List<MessageDto> rows = Lists.newArrayList();

	public MessageTableModel() {
	}

	public void addRows(List<MessageDto> messageDtos) {
		this.rows.addAll(messageDtos);
		int insertedRowIndex = getRowCount() - 1;
		fireTableRowsInserted(insertedRowIndex, insertedRowIndex);
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
		switch(COLUMNS[columnIndex]) {
			case NAME: {
				MessageDto dto = rows.get(rowIndex); 
				dto.setName((String)val);
				MessageLogic.getInstance().updateMessage(dto);
				break;
			}
			case REMARK: {
				MessageDto dto = rows.get(rowIndex); 
				dto.setRemark((String)val);
				MessageLogic.getInstance().updateMessage(dto);
				break;
			}
			default:
				throw new IllegalArgumentException();
		}
	}

	public int getDefaultColumnWidth(int columnIndex) {
		return COLUMNS[columnIndex].getWidth();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		return getColumnValue(rows.get(rowIndex), columnIndex);
	}
	private String getColumnValue(MessageDto row, int columnIndex) {
		switch(COLUMNS[columnIndex]) {
			case NAME: {
				return row.getName();
			}
			case REMARK: {
				return row.getRemark();
			}
			case METHOD: {
				return row.getMethod();
			}
			case URL: {
				return row.getUrl();
			}
			case PARAMS: {
				return Integer.toString(row.getParams());
			}
			case STATUS: {
				return row.getStatus() != null ? Short.toString(row.getStatus()) : "";
			}
			case LENGTH: {
				return row.getLength() != null ? Integer.toString(row.getLength()) : "";
			}
			case MIME_TYPE: {
				return row.getMimeType() != null ? row.getMimeType() : "";
			}
			case COOKIES: {
				return row.getCookies() != null ? row.getCookies() : "";
			}
			default: {
				return "";
			}
		}
	}

}