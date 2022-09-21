package okuken.iste.view.message.table;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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
import okuken.iste.view.chain.ChainDefPanel;

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
			private Integer lastSelectedMessageId;
			@Override
			public void changeSelection(int row, int col, boolean toggle, boolean extend) {
				super.changeSelection(row, col, toggle, extend);
				if(row < 0) {
					return;
				}

				var modelRowIndex = table.convertRowIndexToModel(row);
				var modelColumnIndex = table.convertColumnIndexToModel(col);
				tableModel.fireTableCellUpdated(modelRowIndex, modelColumnIndex); // for update selecting cell's color forcefully (if not, to click same row and right cell doesn't happen repaint background of the cell...)

				var currentSelectedMessageDto = tableModel.getRow(modelRowIndex);
				try {
					if(lastSelectedMessageId == null || !lastSelectedMessageId.equals(currentSelectedMessageDto.getId())) {
						Controller.getInstance().refreshMessageDetailPanels(currentSelectedMessageDto);
					}
				} finally {
					lastSelectedMessageId = currentSelectedMessageDto.getId();
				}
			}
		};
		table.setComponentPopupMenu(new MessageTablePopupMenu(this, table));
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if(e.getClickCount() != 2) {
					return;
				}
				var rowIndex = table.rowAtPoint(e.getPoint());
				if(rowIndex < 0) {
					return;
				}

				var messageDto = tableModel.getRow(table.convertRowIndexToModel(rowIndex));
				ChainDefPanel.openChainFrame(messageDto, table);
			}
		});
		UiUtil.setupStopEditingOnFocusLost(table);
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
				var columnType = tableModel.getColumnType(table.convertColumnIndexToModel(column));

				setHorizontalAlignment(columnType.getHorizontalAlignment());

				if(isSelected) {
					setBorder(selectedRowBorder);
				} else {
					setBorder(defaultRowBorder);
				}

				if(isSelected && column == table.getSelectedColumn()) {
					return renderer;
				}

				if(columnType.isProgressDetail() &&
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
		UiUtil.stopEditing(table);
		if(messageFilterDto.getProgresses() == null) {
			return table.getRowCount();
		}
		// memorize selection
		var selectedRowModelIndexs = getSelectedRowIndexs();
		var nextRowModelIndex = UiUtil.getNextTableModelRow(selectedRowModelIndexs, table);
		var selectedColumn = table.getSelectedColumn();

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

		// apply selection
		var selectedRowMax = selectedRowModelIndexs.stream()
				.map(table::convertRowIndexToView)
				.filter(row -> row > -1)
				.max(Integer::compareTo);
		if(selectedRowMax.isPresent()) {
			table.changeSelection(selectedRowMax.get(), selectedColumn, false, false);
		} else if(nextRowModelIndex != null) {
			var nextRowIndex = table.convertRowIndexToView(nextRowModelIndex);
			if(nextRowIndex > -1) {
				table.changeSelection(nextRowIndex, selectedColumn, false, false);
				SwingUtilities.invokeLater(() -> {
					table.changeSelection(nextRowIndex, selectedColumn, false, false);
				});
			}
		}

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

	public MessageTableColumn getSelectedColumnType() {
		return tableModel.getColumnType(
				table.convertColumnIndexToModel(table.getSelectedColumn()));
	}

	public String getSelectedMessagesForCopyToClipboad() {
		return tableModel.getRowsAsTsv(
				Arrays.stream(table.getSelectedRows()).map(table::convertRowIndexToModel).toArray(),
				IntStream.range(0, table.getColumnCount()).map(table::convertColumnIndexToModel).toArray());
	}

}