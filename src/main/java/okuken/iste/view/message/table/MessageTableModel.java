package okuken.iste.view.message.table;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.table.AbstractTableModel;

import com.google.common.collect.Lists;

import okuken.iste.dto.MessageDto;
import okuken.iste.enums.SecurityTestingProgress;
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
			MessageTableColumn.PROGRESS_MEMO,
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
				if(val.equals(dto.getName())) {
					break;
				}

				dto.setName((String)val);
				MessageLogic.getInstance().updateMessage(dto);
				break;
			}
			case REMARK: {
				MessageDto dto = rows.get(rowIndex); 
				if(val.equals(dto.getRemark())) {
					break;
				}

				dto.setRemark((String)val);
				MessageLogic.getInstance().updateMessage(dto);
				break;
			}
			case PROGRESS: {
				SecurityTestingProgress progress = (SecurityTestingProgress)val;

				MessageDto dto = rows.get(rowIndex); 
				if(progress == dto.getProgress()) {
					break;
				}

				dto.setProgress(progress);
				MessageLogic.getInstance().updateMessage(dto);
				break;
			}
			case PROGRESS_MEMO: {
				MessageDto dto = rows.get(rowIndex); 
				if(val.equals(dto.getProgressMemo())) {
					break;
				}

				dto.setProgressMemo((String)val);
				MessageLogic.getInstance().updateMessage(dto);
				break;
			}
			default:
				throw new IllegalArgumentException();
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
		String value;
		switch(COLUMNS[columnIndex]) {
			case NAME: {
				value = row.getName();
				break;
			}
			case REMARK: {
				value = row.getRemark();
				break;
			}
			case PROGRESS: {
				value = row.getProgress().getCaption();
				break;
			}
			case PROGRESS_MEMO: {
				value = row.getProgressMemo();
				break;
			}
			case PROTOCOL: {
				value = row.getProtocol();
				break;
			}
			case HOST: {
				value = row.getHost();
				break;
			}
			case PORT: {
				Integer port = row.getPortIfNotDefault();
				value = port != null ? Integer.toString(port) : "";
				break;
			}
			case PATH: {
				value = row.getPath();
				break;
			}
			case QUERY: {
				value = row.getQuery();
				break;
			}
			case URL: {
				value = row.getUrlShortest();
				break;
			}
			case METHOD: {
				value = row.getMethod();
				break;
			}
			case PARAMS: {
				value = Integer.toString(row.getParams());
				break;
			}
			case STATUS: {
				value = row.getStatus() != null ? Short.toString(row.getStatus()) : "";
				break;
			}
			case LENGTH: {
				value = row.getLength() != null ? Integer.toString(row.getLength()) : "";
				break;
			}
			case MIME_TYPE: {
				value = row.getMimeType();
				break;
			}
			case COOKIES: {
				value = row.getCookies();
				break;
			}
			default: {
				return "";
			}
		}
		return Optional.ofNullable(value).orElse("");
	}

}