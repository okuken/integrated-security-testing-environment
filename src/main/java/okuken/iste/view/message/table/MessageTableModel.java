package okuken.iste.view.message.table;

import java.util.List;

import javax.swing.table.AbstractTableModel;

import com.google.common.collect.Lists;

import okuken.iste.dto.MessageDto;

public class MessageTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;

	private static final MessageTableColumn[] COLUMNS = {
			MessageTableColumn.NAME,
			MessageTableColumn.URL,
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

	public void clearRows() {
		int rowCount = getRowCount();
		if(rowCount > 0) {
			this.rows.clear();
			fireTableRowsDeleted(0, rowCount - 1);
		}
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
		rows.get(rowIndex).setName((String)val);
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
				return Short.toString(row.getStatus());
			}
			case LENGTH: {
				return Integer.toString(row.getLength());
			}
			case MIME_TYPE: {
				return row.getMimeType();
			}
			case COOKIES: {
				return row.getCookies();
			}
			default: {
				return "";
			}
		}
	}

}