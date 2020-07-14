package okuken.iste.view.repeater;

import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.util.SqlUtil;
import java.awt.BorderLayout;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;

public class RepeatTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTable table;
	private DefaultTableModel tableModel;
	private JScrollPane scrollPane;

	private List<MessageRepeatDto> repeaterHistory;

	@SuppressWarnings("serial")
	public RepeatTablePanel() {
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
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scrollPane.setViewportView(table);
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"Send date", "Status", "Length", "Time", "Diff"
			}
		) {
			boolean[] columnEditables = new boolean[] {
				false, false, false, false, false
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		});
		table.getColumnModel().getColumn(0).setPreferredWidth(150);
		table.getColumnModel().getColumn(1).setPreferredWidth(50);
		table.getColumnModel().getColumn(2).setPreferredWidth(50);
		table.getColumnModel().getColumn(3).setPreferredWidth(50);
		table.getColumnModel().getColumn(4).setPreferredWidth(600);

		tableModel = (DefaultTableModel)table.getModel();
	}

	public void setup(Integer orgMessageId) {
		clearRows();
		repeaterHistory = Controller.getInstance().getRepeaterHistory(orgMessageId);
		repeaterHistory.forEach(messageRepeatDto -> {
			tableModel.addRow(new Object[] {
					SqlUtil.dateToString(messageRepeatDto.getSendDate()),
					messageRepeatDto.getStatus(),
					messageRepeatDto.getLength(),
					messageRepeatDto.getTime(),
					messageRepeatDto.getDifference()});
		});
	}
	private void clearRows() {
		int rowCount = tableModel.getRowCount();
		if (rowCount < 1) {
			return;
		}

		for(int i = rowCount - 1; i >= 0; i--) {
			tableModel.removeRow(i);
		}
		tableModel.fireTableRowsDeleted(0, rowCount - 1);

		repeaterHistory = null;
	}

	public void clear() {
		clearRows();
	}

	public Integer selectLastRow() {
		if (repeaterHistory.isEmpty()) {
			return null;
		}
		int lastIndex = repeaterHistory.size() - 1;
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

}
