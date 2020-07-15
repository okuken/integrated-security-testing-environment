package okuken.iste.view.message.table;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.Arrays;
import java.util.Enumeration;

import javax.swing.DefaultCellEditor;
import javax.swing.DropMode;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

import okuken.iste.controller.Controller;
import okuken.iste.enums.SecurityTestingProgress;
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
			@Override
			public void changeSelection(int row, int col, boolean toggle, boolean extend) {
				super.changeSelection(row, col, toggle, extend);
				Controller.getInstance().refreshMessageDetailPanels(tableModel.getRow(row));
			}
		};
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
		table.setComponentPopupMenu(new MessageTablePopupMenu());
		UiUtil.setupCtrlCAsCopyCell(table);
	}

	private void setupColumnWidth(JTable table, MessageTableModel messageTableModel) {
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		Enumeration<TableColumn> e = table.getColumnModel().getColumns();
		for (int i = 0; e.hasMoreElements(); i++) {
			e.nextElement().setPreferredWidth(messageTableModel.getDefaultColumnWidth(i));
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
		@SuppressWarnings("serial")
		TableCellRenderer tableCellRenderer = new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
				Component renderer = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
				if(isSelected && !MessageTableColumn.PROGRESS.getCaption().equals(table.getColumnName(column))) {
					return renderer;
				}

				setBackground(tableModel.getRow(row).getProgress().getColor());

				return renderer;
			}
		};

		Enumeration<TableColumn> e = table.getColumnModel().getColumns();
		while (e.hasMoreElements()) {
			e.nextElement().setCellRenderer(tableCellRenderer);
		}
	}

}