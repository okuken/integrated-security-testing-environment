package okuken.iste.view.message.table;

import java.awt.BorderLayout;
import java.util.Enumeration;

import javax.swing.DropMode;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.TableColumn;

import okuken.iste.controller.Controller;

public class MessageTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public MessageTablePanel() {
		setLayout(new BorderLayout(0, 0));
		
		MessageTableModel tableModel = new MessageTableModel();
		Controller.getInstance().setMessageTableModel(tableModel);

		JTable table = new JTable(tableModel) {
			private static final long serialVersionUID = 1L;
			@Override
			public void changeSelection(int row, int col, boolean toggle, boolean extend) {
				super.changeSelection(row, col, toggle, extend);
				Controller.getInstance().refreshRequestDetailPanel();
			}
		};
		setupColumnWidth(table, tableModel);
		setupDraggable(table);
		Controller.getInstance().setMessageTable(table);	

		JScrollPane scrollPane = new JScrollPane(table);

		add(scrollPane);
	}

	private void setupColumnWidth(JTable table, MessageTableModel messageTableModel) {
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		Enumeration<TableColumn> e = table.getColumnModel().getColumns();
		for (int i = 0; e.hasMoreElements(); i++) {
			e.nextElement().setPreferredWidth(messageTableModel.getDefaultColumnWidth(i));
		}
	}

	private void setupDraggable(JTable table) {
		table.setDragEnabled(true);
		table.setDropMode(DropMode.INSERT_ROWS);
//		table.setTransferHandler;//TODO: implement
	}
}