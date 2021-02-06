package okuken.iste.view.message.table;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.DropMode;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageFilterDto;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.logic.MessageFilterLogic;
import okuken.iste.util.UiUtil;

public class MessageTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private MessageTableModel tableModel;
	private JTable table;

	public MessageTablePanel() {
		setLayout(new BorderLayout(0, 0));
		
		tableModel = new MessageTableModel();
		Controller.getInstance().setMessageTableModel(tableModel);

		table = new JTable(tableModel) {
			private static final long serialVersionUID = 1L;
			private Integer lastSelectedModelRowIndex;
			@Override
			public void changeSelection(int row, int col, boolean toggle, boolean extend) {
				super.changeSelection(row, col, toggle, extend);

				var modelRowIndex = table.convertRowIndexToModel(row);
				var modelColumnIndex = table.convertColumnIndexToModel(col);
				tableModel.fireTableCellUpdated(modelRowIndex, modelColumnIndex); // for update selecting cell's color forcefully (if not, to click same row and right cell doesn't happen repaint background of the cell...)

				try {
					if(lastSelectedModelRowIndex == null || !lastSelectedModelRowIndex.equals(modelRowIndex)) {
						Controller.getInstance().refreshMessageDetailPanels(tableModel.getRow(modelRowIndex));
					}
				} finally {
					lastSelectedModelRowIndex = modelRowIndex;
				}
			}
		};
		table.setComponentPopupMenu(new MessageTablePopupMenu());
		setupTable();
		Controller.getInstance().setMessageTable(table);	

		SwingUtilities.invokeLater(() -> { // run after IBurpExtenderCallbacks#customizeUiComponent().
			table.getTableHeader().setReorderingAllowed(true);
		});

		JScrollPane scrollPane = new JScrollPane(table);

		add(scrollPane);

		Controller.getInstance().setMessageTablePanel(this);
	}

	public void setupTable() {
		setupColumnWidth(table, tableModel);
		setupDraggable(table, tableModel);
		setupProgressColumn(table, tableModel);
		setupTableRowColorControl(table, tableModel);
		UiUtil.setupCtrlCAsCopyCell(table, colIndex -> tableModel.getColumnIndex(MessageTableColumn.getByCaption(table.getColumnName(colIndex))));
		table.setRowSorter(null);
	}

	private void setupColumnWidth(JTable table, MessageTableModel messageTableModel) {
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		Enumeration<TableColumn> e = table.getColumnModel().getColumns();
		for (int i = 0; e.hasMoreElements(); i++) {
			e.nextElement().setPreferredWidth(MessageTableColumn.getByCaption(table.getColumnName(i)).getWidth());
		}
	}

	private void setupDraggable(JTable table, MessageTableModel messageTableModel) {
		table.setDragEnabled(true);
		table.setDropMode(DropMode.INSERT_ROWS);
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setTransferHandler(new MessageTableTransferHandler(table, messageTableModel));
	}

	private void setupProgressColumn(JTable table, MessageTableModel messageTableModel) {
		TableColumn progressColumn = table.getColumnModel().getColumn(messageTableModel.getColumnIndex(MessageTableColumn.PROGRESS));

		JComboBox<SecurityTestingProgress> progressComboBox = new JComboBox<SecurityTestingProgress>();
		Arrays.stream(SecurityTestingProgress.values()).forEach(progress -> progressComboBox.addItem(progress));
		progressComboBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().applyMessageFilter();
			}
		});
		progressColumn.setCellEditor(new DefaultCellEditor(progressComboBox));
	}

	private void setupTableRowColorControl(JTable table, MessageTableModel tableModel) {
		Border defaultRowBorder = BorderFactory.createEmptyBorder(2, 0, 2, 0);
		Border selectedRowBorder = BorderFactory.createMatteBorder(2, 0, 2, 0, Colors.TABLE_ROW_SELECTED_BORDER);

		@SuppressWarnings("serial")
		TableCellRenderer tableCellRenderer = new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
				Component renderer = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

				if(isSelected) {
					setBorder(selectedRowBorder);
				} else {
					setBorder(defaultRowBorder);
				}

				if(isSelected && column == table.getSelectedColumn()) {
					return renderer;
				}

				if(tableModel.getColumnType(table.convertColumnIndexToModel(column)).isProgressDetail() &&
					(StringUtils.startsWith((CharSequence) value, "/") || StringUtils.startsWith((CharSequence) value, "-"))) { //personal spec...
					setBackground(SecurityTestingProgress.DONE.getColor());
				} else {
					setBackground(tableModel.getRow(table.convertRowIndexToModel(row)).getProgress().getColor());
				}

				return renderer;
			}
		};

		Enumeration<TableColumn> e = table.getColumnModel().getColumns();
		while (e.hasMoreElements()) {
			e.nextElement().setCellRenderer(tableCellRenderer);
		}
	}

	public int applyFilter(MessageFilterDto messageFilterDto) {
		if(messageFilterDto.getProgresses() == null) {
			return table.getRowCount();
		}
		var selectedRowIndexs = getSelectedRowIndexs(); // memorize selection

		var tableRowSorter = new TableRowSorter<MessageTableModel>(tableModel);
		tableRowSorter.setRowFilter(new RowFilter<MessageTableModel, Integer>() {
			@SuppressWarnings("rawtypes")
			public boolean include(Entry entry) {
				var messageDto = tableModel.getRow((Integer)entry.getIdentifier());
				return MessageFilterLogic.getInstance().include(messageDto, messageFilterDto);
			}
		});

		IntStream.range(0, table.getColumnCount()).forEach(i -> {
			tableRowSorter.setSortable(i, false);
		});

		table.setRowSorter(tableRowSorter);

		selectedRowIndexs.stream()
			.map(table::convertRowIndexToView)
			.forEach(row -> {table.getSelectionModel().addSelectionInterval(row, row);}); // apply selection

		return table.getRowCount();
	}

	public List<MessageDto> getMessages() {
		return tableModel.getRows();
	}

	public List<Integer> getSelectedRowIndexs() {
		return Arrays.stream(table.getSelectedRows())
				.mapToObj(table::convertRowIndexToModel)
				.collect(Collectors.toList());
	}

	public List<MessageDto> getSelectedMessages() {
		return getSelectedRowIndexs().stream()
				.map(tableModel::getRow)
				.collect(Collectors.toList());
	}

	public String getSelectedMessagesForCopyToClipboad() {
		return tableModel.getRowsAsTsv(
				Arrays.stream(table.getSelectedRows()).map(table::convertRowIndexToModel).toArray());
	}

}