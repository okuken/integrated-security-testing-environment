package okuken.iste.view.message.table;

import java.util.List;

import javax.swing.table.AbstractTableModel;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;

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

	private List<MessageTableModelRow> rows = Lists.newArrayList();

	public MessageTableModel() {
	}

	public void addRows(IHttpRequestResponse[] messages) {
		for(IHttpRequestResponse message: messages) {
			this.rows.add(MessageTableModelRow.create(message, message.getComment()));
		}
		
		int insertedRowIndex = getRowCount() - 1;
		fireTableRowsInserted(insertedRowIndex, insertedRowIndex);
	}

	public IHttpRequestResponse getRowMessage(int rowIndex) {
		return rows.get(rowIndex).getHttpRequestResponse();
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
	private String getColumnValue(MessageTableModelRow row, int columnIndex) {
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
				return row.getParams();
			}
			case STATUS: {
				return row.getStatus();
			}
			case LENGTH: {
				return row.getLength();
			}
			case MIME_TYPE: {
				return row.getMimeType();
			}
			case COMMENT: {
				return row.getComment();
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