package okuken.iste.view.common;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
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

	private List<Runnable> editListeners = Lists.newArrayList();

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
				if(column.isEditable()) {
					afterEdit();
				}
				super.setValueAt(val, rowIndex, columnIndex);
			}
		});
		columns.stream().forEach(column -> {
			table.getColumnModel().getColumn(column.getIndex()).setPreferredWidth(column.getWidth());
		});
		tablePanel.add(table.getTableHeader(), BorderLayout.NORTH);
		tablePanel.add(table);
		
		UiUtil.setupStopEditingOnFocusLost(table);
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
		
		JButton upRowButton = new JButton(Captions.TABLE_CONTROL_BUTTON_UP);
		upRowButton.setToolTipText(Captions.TABLE_CONTROL_BUTTON_UP_TT);
		upRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				upRows(getSelectedRowIndexsReversed());
			}
		});
		headerRightPanel.add(upRowButton);
		
		JButton downRowButton = new JButton(Captions.TABLE_CONTROL_BUTTON_DOWN);
		downRowButton.setToolTipText(Captions.TABLE_CONTROL_BUTTON_DOWN_TT);
		downRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				downRows(getSelectedRowIndexsReversed());
			}
		});
		headerRightPanel.add(downRowButton);
		
		headerRightPanel.add(UiUtil.createSpacer());
		
		JButton deleteRowButton = new JButton(Captions.TABLE_CONTROL_BUTTON_DELETE);
		deleteRowButton.setToolTipText(Captions.TABLE_CONTROL_BUTTON_DELETE_TT);
		deleteRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				removeRows(getSelectedRowIndexsReversed());
			}
		});
		
		headerRightPanel.add(deleteRowButton);
		
		JButton addRowButton = new JButton(Captions.TABLE_CONTROL_BUTTON_ADD);
		addRowButton.setToolTipText(Captions.TABLE_CONTROL_BUTTON_ADD_TT);
		addRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				addRow(UiUtil.judgeIsShiftDown(e));
			}
		});
		headerRightPanel.add(addRowButton);

		afterInit(table, tableModel);
	}

	private List<Integer> getSelectedRowIndexsReversed() {
		List<Integer> selectedRows = getSelectedRowIndexs();
		Collections.reverse(selectedRows);
		return selectedRows;
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

	private void addRow(boolean insert) {
		if(dtos.size() >= getMaxRowSize()) {
			return; //TODO: show error message
		}

		var insertIndex = dtos.size();
		if(insert) {
			var selectedIndexes = getSelectedRowIndexs();
			if(!selectedIndexes.isEmpty()) {
				insertIndex = selectedIndexes.get(0);
			}
		}

		addRow(createRowDto(), insertIndex);
	}
	public void addRow(T dto) {
		addRow(dto, dtos.size());
	}
	public void addRow(T dto, int index) {
		dtos.add(index, dto);
		tableModel.insertRow(index, convertDtoToObjectArray(dto));
		afterAddRow(dto);
		afterEdit();
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

	private void upRows(List<Integer> selectedRowsReversed) {
		if(selectedRowsReversed.isEmpty()) {
			return;
		}

		var top = selectedRowsReversed.get(selectedRowsReversed.size() - 1);
		var target = top - 1 >= 0 ? top - 1 : top;

		var movedDtos = moveRows(target, selectedRowsReversed);

		afterUpRows(movedDtos);
		afterEdit();
	}

	private void downRows(List<Integer> selectedRowsReversed) {
		if(selectedRowsReversed.isEmpty()) {
			return;
		}

		var bottom = selectedRowsReversed.get(0);
		var finalTarget = bottom + 1 < dtos.size() ? bottom + 1 : bottom;
		var target = finalTarget - selectedRowsReversed.size() + 1;

		var movedDtos = moveRows(target, selectedRowsReversed);

		afterDownRows(movedDtos);
		afterEdit();
	}

	private List<T> moveRows(int to, List<Integer> selectedRowsReversed) {
		var movingDtos = new ArrayList<T>();
		selectedRowsReversed.forEach(selectedRow -> {
			var dto = dtos.get(selectedRow);

			movingDtos.add(dto);
			dtos.remove(dto);
			tableModel.removeRow(selectedRow);
		});

		movingDtos.forEach(movingDto -> {
			dtos.add(to, movingDto);
			tableModel.insertRow(to, convertDtoToObjectArray(movingDto));
		});

		table.getSelectionModel().addSelectionInterval(to, to + selectedRowsReversed.size() - 1);

		return movingDtos;
	}

	private void removeRows(List<Integer> selectedRowsReversed) {
		List<T> removedRows = Lists.newArrayList();

		selectedRowsReversed.forEach(selectedRow -> {
			var dto = dtos.get(selectedRow);

			removedRows.add(dto);
			dtos.remove(dto);
			tableModel.removeRow(selectedRow);

			afterRemoveRow(dto);
		});

		afterRemoveRows(removedRows);
		afterEdit();
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

	public void stopEditing() {
		UiUtil.stopEditing(table);
	}

	public void addEditListener(Runnable listener) {
		editListeners.add(listener);
	}

	private void afterEdit() {
		editListeners.forEach(Runnable::run);
	}

	public List<T> getRows() {
		return dtos;
	}

	protected int getMaxRowSize() {
		return Integer.MAX_VALUE;
	}

	protected void afterUpRows(List<T> dtos) {}
	protected void afterDownRows(List<T> dtos) {}
	protected void afterRemoveRows(List<T> dtos) {}

	abstract protected List<ColumnDef> getColumnDefs();
	abstract protected String getTableCaption();
	abstract protected List<T> loadRowDtos();

	abstract protected void afterInit(JTable table, DefaultTableModel tableModel);
	abstract protected void afterSetValueAt(Object val, int rowIndex, int columnIndex, T dto);
	abstract protected void afterAddRow(T dto);
	abstract protected void afterRemoveRow(T dto);

	abstract protected T createRowDto();

}
