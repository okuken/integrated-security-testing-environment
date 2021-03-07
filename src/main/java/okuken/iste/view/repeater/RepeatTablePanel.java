package okuken.iste.view.repeater;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.logic.RepeaterLogic;
import okuken.iste.util.SqlUtil;
import java.awt.BorderLayout;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

public class RepeatTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private static final int COLNUM_NO = 0;
	private static final int COLNUM_SEND_DATE = 1;
	private static final int COLNUM_AUTH = 2;
	private static final int COLNUM_STATUS = 3;
	private static final int COLNUM_LENGTH = 4;
	private static final int COLNUM_TIME = 5;
	private static final int COLNUM_CHAIN = 6;
	private static final int COLNUM_DIFF = 7;
	private static final int COLNUM_MEMO = 8;

	private JTable table;
	private DefaultTableModel tableModel;
	private JScrollPane scrollPane;

	private List<MessageRepeatDto> repeaterHistory;

	private RepeaterPanel parentRepeaterPanel;

	@SuppressWarnings("serial")
	public RepeatTablePanel(RepeaterPanel parentRepeaterPanel) {
		this.parentRepeaterPanel = parentRepeaterPanel;
		setLayout(new BorderLayout(0, 0));
		
		scrollPane = new JScrollPane();
		add(scrollPane);
		
		table = new JTable() {
			@Override
			public void changeSelection(int row, int col, boolean toggle, boolean extend) {
				super.changeSelection(row, col, toggle, extend);
				Controller.getInstance().refreshMessageRepeaterPanel(row);
			}
		};
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		scrollPane.setViewportView(table);
		table.setModel(new DefaultTableModel(
			new Object[][] {
				{null, null, null, null, null, null, null, null, null},
			},
			new String[] {
				"No", "Send date", "Auth", "Status", "Length", "Time", "Chain", "Diff", "Notes"
			}
		) {
			boolean[] columnEditables = new boolean[] {
				false, false, false, false, false, false, false, false, true
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
			@Override
			public void setValueAt(Object val, int rowIndex, int columnIndex) {
				if(columnIndex != COLNUM_MEMO) {
					super.setValueAt(val, rowIndex, columnIndex);
					return;
				}

				MessageRepeatDto dto = repeaterHistory.get(rowIndex);
				if(val.equals(dto.getMemo())) {
					super.setValueAt(val, rowIndex, columnIndex);
					return;
				}

				dto.setMemo((String)val);
				RepeaterLogic.getInstance().updateMemo(dto);
				super.setValueAt(val, rowIndex, columnIndex);
			}
		});
		table.getColumnModel().getColumn(COLNUM_NO).setPreferredWidth(25);
		table.getColumnModel().getColumn(COLNUM_SEND_DATE).setPreferredWidth(150);
		table.getColumnModel().getColumn(COLNUM_AUTH).setPreferredWidth(100);
		table.getColumnModel().getColumn(COLNUM_STATUS).setPreferredWidth(50);
		table.getColumnModel().getColumn(COLNUM_LENGTH).setPreferredWidth(50);
		table.getColumnModel().getColumn(COLNUM_TIME).setPreferredWidth(50);
		table.getColumnModel().getColumn(COLNUM_CHAIN).setPreferredWidth(35);
		table.getColumnModel().getColumn(COLNUM_DIFF).setPreferredWidth(300);
		table.getColumnModel().getColumn(COLNUM_MEMO).setPreferredWidth(400);

		table.removeColumn(table.getColumnModel().getColumn(COLNUM_DIFF)); //TODO: impl

		table.setComponentPopupMenu(new RepeatTablePopupMenu(this));

		tableModel = (DefaultTableModel)table.getModel();
	}

	private Object[] convertHistoryIndexToRow(Integer index) {
		return convertHistoryToRow(index, repeaterHistory.get(index));
	}
	private Object[] convertHistoryToRow(int index, MessageRepeatDto messageRepeatDto) {
		return new Object[] {
				Integer.toString(index + 1),
				SqlUtil.dateToPresentationString(messageRepeatDto.getSendDate()),
				Optional.ofNullable(messageRepeatDto.getUserId()).orElse(""),
				messageRepeatDto.getStatus(),
				messageRepeatDto.getLength(),
				messageRepeatDto.getTime(),
				messageRepeatDto.isChainFlag() ? Captions.CHECK : "",
				messageRepeatDto.getDifference(),
				Optional.ofNullable(messageRepeatDto.getMemo()).orElse("")};
	}

	public void setup(List<MessageRepeatDto> repeaterHistory) {
		clearRows();
		this.repeaterHistory = repeaterHistory;
		IntStream.range(0, repeaterHistory.size()).mapToObj(this::convertHistoryIndexToRow).forEach(tableModel::addRow);
	}
	private void clearRows() {
		int rowCount = tableModel.getRowCount();
		if (rowCount < 1) {
			return;
		}

		for(int i = rowCount - 1; i >= 0; i--) {
			tableModel.removeRow(i);
		}

		repeaterHistory = null;
	}

	public void addRow(MessageRepeatDto messageRepeatDto) {
		repeaterHistory.add(messageRepeatDto);
		tableModel.addRow(convertHistoryToRow(tableModel.getRowCount(), messageRepeatDto));
	}

	public void applyResponseInfoToRow(MessageRepeatDto messageRepeatDto) {
		var row = repeaterHistory.indexOf(messageRepeatDto);
		tableModel.setValueAt(messageRepeatDto.getStatus(), row, COLNUM_STATUS);
		tableModel.setValueAt(messageRepeatDto.getLength(), row, COLNUM_LENGTH);
		tableModel.setValueAt(messageRepeatDto.getTime(), row, COLNUM_TIME);
	}

	public boolean judgeIsSelected(MessageRepeatDto messageRepeatDto) {
		return table.getSelectedRow() == repeaterHistory.indexOf(messageRepeatDto);
	}

	public void clear() {
		clearRows();
	}

	public Integer selectLastRow() {
		if (tableModel.getRowCount() <= 0) {
			return null;
		}
		int lastIndex = tableModel.getRowCount() - 1;
		table.setRowSelectionInterval(lastIndex, lastIndex);

		SwingUtilities.invokeLater(() -> {
			JScrollBar scrollBar = scrollPane.getVerticalScrollBar();
			scrollBar.setValue(scrollBar.getMaximum());
		});

		return lastIndex;
	}

	public MessageRepeatDto getRow(int rowIndex) {
		return repeaterHistory.get(rowIndex);
	}

	public List<MessageRepeatDto> getSelectedRows() {
		return Arrays.stream(table.getSelectedRows())
				.mapToObj(repeaterHistory::get)
				.collect(Collectors.toList());
	}

	public RepeaterPanel getParentRepeaterPanel() {
		return parentRepeaterPanel;
	}

}
