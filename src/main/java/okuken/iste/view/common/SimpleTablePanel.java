package okuken.iste.view.common;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableModel;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.util.UiUtil;

import javax.swing.JLabel;

public abstract class SimpleTablePanel<T> extends JPanel {

	private static final long serialVersionUID = 1L;

	private List<ColumnDef> columns;

	protected List<T> dtos = Lists.newArrayList();
	protected JTable table;
	protected DefaultTableModel tableModel;

	@SuppressWarnings("serial")
	public SimpleTablePanel() {
		
		this.columns = getColumnDefs();
		
		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout(0, 0));
		add(mainPanel);
		
		JPanel tablePanel = new JPanel();
		tablePanel.setLayout(new BorderLayout(0, 0));
		mainPanel.add(tablePanel);
		
		table = new JTable();
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			columns.stream().map(column -> column.getCaption()).toArray()
		) {
			@Override
			@SuppressWarnings({ "unchecked", "rawtypes" })
			public Class getColumnClass(int columnIndex) {
				return columns.get(columnIndex).getType();
			}
			@Override
			public boolean isCellEditable(int rowIndex, int columnIndex) {
				return columns.get(columnIndex).isEditable();
			}
			@Override
			public void setValueAt(Object val, int rowIndex, int columnIndex) {
				var column = columns.get(columnIndex);
				var dto = dtos.get(rowIndex);

				try {
					if(column.getGetter() != null && column.getSetter() != null) {
						if(val.equals(column.getGetter().invoke(dto))) { //case: no change
							return;
						}
						column.getSetter().invoke(dto, val);
					}
				} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					throw new RuntimeException(e);
				}

				afterSetValueAt(val, rowIndex, columnIndex, dto);
				super.setValueAt(val, rowIndex, columnIndex);
			}
		});
		columns.stream().forEach(column -> {
			table.getColumnModel().getColumn(column.getIndex()).setPreferredWidth(column.getWidth());
		});
		tablePanel.add(table.getTableHeader(), BorderLayout.NORTH);
		tablePanel.add(table);
		
		UiUtil.setupCtrlCAsCopyCell(table);
		SwingUtilities.invokeLater(() -> {
			table.setBorder(new LineBorder(Colors.TABLE_BORDER));
		});
		
		tableModel = (DefaultTableModel) table.getModel();
		
		JPanel headerPanel = new JPanel();
		headerPanel.setLayout(new BorderLayout(0, 0));
		mainPanel.add(headerPanel, BorderLayout.NORTH);
		
		JPanel headerLeftPanel = new JPanel();
		headerPanel.add(headerLeftPanel, BorderLayout.WEST);
		headerLeftPanel.setLayout(new BorderLayout(0, 0));
		
		JLabel lblTableCaption = new JLabel(getTableCaption() + ":");
		headerLeftPanel.add(lblTableCaption, BorderLayout.SOUTH);
		
		JPanel panel = new JPanel();
		headerPanel.add(panel, BorderLayout.CENTER);
		
		JPanel headerRightPanel = new JPanel();
		FlowLayout flowLayout_1 = (FlowLayout) headerRightPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.RIGHT);
		headerPanel.add(headerRightPanel, BorderLayout.EAST);
		
		JButton deleteRowButton = new JButton(Captions.TABLE_CONTROL_BUTTON_DELETE);
		deleteRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				List<Integer> selectedRows = getSelectedRowIndexs();
				Collections.reverse(selectedRows);
				removeRows(selectedRows);
			}
		});
		
		headerRightPanel.add(deleteRowButton);
		
		JButton addRowButton = new JButton(Captions.TABLE_CONTROL_BUTTON_ADD);
		addRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				addRow();
			}
		});
		headerRightPanel.add(addRowButton);

		afterInit(table, tableModel);
	}

	private List<Integer> getSelectedRowIndexs() {
		return Arrays.stream(table.getSelectedRows())
				.mapToObj(Integer::valueOf)
				.collect(Collectors.toList());
	}
	public List<T> getSelectedRows() {
		return getSelectedRowIndexs().stream()
				.map(dtos::get)
				.collect(Collectors.toList());
	}

	private void addRow() {
		if(dtos.size() >= getMaxRowSize()) {
			return; //TODO: show error message
		}
		addRow(createRowDto());
	}
	public void addRow(T dto) {
		dtos.add(dto);
		tableModel.addRow(convertDtoToObjectArray(dto));
		afterAddRow(dto);
	}
	private Object[] convertDtoToObjectArray(T dto) {
		return columns.stream().map(column -> {
			try {
				if(column.getGetter() == null) {
					return "";
				}
				return column.getGetter().invoke(dto);
			} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
				e.printStackTrace();
				return null;
			}
		}).toArray();
	}

	private void removeRows(List<Integer> selectedRowsReversed) {
		selectedRowsReversed.forEach(selectedRow -> {
			var dto = dtos.get(selectedRow);

			dtos.remove(dto);
			tableModel.removeRow(selectedRow);

			afterRemoveRow(dto);
		});
	}

	/**
	 * CAUTION: This method does not call afterRemoveRow method
	 */
	private void clearRows() {
		int rowCount = tableModel.getRowCount();
		if (rowCount < 1) {
			return;
		}

		for(int i = rowCount - 1; i >= 0; i--) {
			tableModel.removeRow(i);
		}
		dtos = null;
	}

	private void loadRows() {
		dtos = loadRowDtos();
		dtos.forEach(dto -> {
			tableModel.addRow(convertDtoToObjectArray(dto));
		});
	}

	public void refreshPanel() {
		clearRows();
		loadRows();
	}

	public void setValueAt(Object value, int row, int col) {
		tableModel.setValueAt(value, row, col);
	}

	public List<T> getRows() {
		return dtos;
	}

	protected int getMaxRowSize() {
		return Integer.MAX_VALUE;
	}

	abstract protected List<ColumnDef> getColumnDefs();
	abstract protected String getTableCaption();
	abstract protected List<T> loadRowDtos();

	abstract protected void afterInit(JTable table, DefaultTableModel tableModel);
	abstract protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, T dto);
	abstract protected void afterAddRow(T dto);
	abstract protected void afterRemoveRow(T dto);

	abstract protected T createRowDto();

}
