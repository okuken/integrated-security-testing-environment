package okuken.iste.view.auth;

import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.logic.AuthLogic;
import okuken.iste.util.UiUtil;

import java.awt.BorderLayout;
import javax.swing.JButton;

import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.border.LineBorder;
import java.awt.Dimension;

public class AuthAccountTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTable table;

	private static final int COLNUM_USER_ID = 0;
	private static final int COLNUM_PASSWORD = 1;
	private static final int COLNUM_REMARK = 2;

	private static final int WIDTH_USER_ID = 100;
	private static final int WIDTH_PASSWORD = 100;
	private static final int WIDTH_REMARK = 300;

	private DefaultTableModel tableModel;

	private List<AuthAccountDto> authAccountDtos;

	@SuppressWarnings("serial")
	public AuthAccountTablePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setPreferredSize(new Dimension(WIDTH_USER_ID + WIDTH_PASSWORD + WIDTH_REMARK + 25, 210));
		add(scrollPane);
		
		table = new JTable();
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				Captions.AUTH_TABLE_FIELD_USER_ID, Captions.AUTH_TABLE_FIELD_PASSWORD, Captions.AUTH_TABLE_FIELD_REMARK
			}
		) {
			@SuppressWarnings("rawtypes")
			Class[] columnTypes = new Class[] {
				String.class, String.class, String.class
			};
			@Override
			@SuppressWarnings({ "unchecked", "rawtypes" })
			public Class getColumnClass(int columnIndex) {
				return columnTypes[columnIndex];
			}
			@Override
			public void setValueAt(Object val, int rowIndex, int columnIndex) {
				AuthAccountDto dto = authAccountDtos.get(rowIndex);
				boolean needRefreshComponentsDependOnAuthAccounts = false;
				switch (columnIndex) {
					case COLNUM_USER_ID:
						if(val.equals(dto.getUserId())) {
							return;
						}
						dto.setUserId((String)val);
						dto.setSessionId(null);
						needRefreshComponentsDependOnAuthAccounts = true;
						break;
					case COLNUM_PASSWORD:
						if(val.equals(dto.getPassword())) {
							return;
						}
						dto.setPassword((String)val);
						dto.setSessionId(null);
						needRefreshComponentsDependOnAuthAccounts = true;
						break;
					case COLNUM_REMARK:
						if(val.equals(dto.getRemark())) {
							return;
						}
						dto.setRemark((String)val);
						break;
					default:
						return;
				}
				AuthLogic.getInstance().saveAuthAccount(dto);
				super.setValueAt(val, rowIndex, columnIndex);
				
				if(needRefreshComponentsDependOnAuthAccounts) {
					Controller.getInstance().refreshComponentsDependOnAuthAccounts();
				}
			}
		});
		table.getColumnModel().getColumn(COLNUM_USER_ID).setPreferredWidth(WIDTH_USER_ID);
		table.getColumnModel().getColumn(COLNUM_PASSWORD).setPreferredWidth(WIDTH_PASSWORD);
		table.getColumnModel().getColumn(COLNUM_REMARK).setPreferredWidth(WIDTH_REMARK);
		scrollPane.setViewportView(table);
		
		UiUtil.setupCtrlCAsCopyCell(table);
		SwingUtilities.invokeLater(() -> { // run after IBurpExtenderCallbacks#customizeUiComponent().
			table.setBorder(new LineBorder(Colors.TABLE_BORDER));
		});
		
		tableModel = (DefaultTableModel) table.getModel();
		
		JPanel authTableHeaderPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) authTableHeaderPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		add(authTableHeaderPanel, BorderLayout.NORTH);
		
		JButton deleteRowButton = new JButton(Captions.AUTH_CONTROL_BUTTON_DELETE);
		deleteRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				List<Integer> selectedRows = Arrays.stream(table.getSelectedRows()).mapToObj(Integer::valueOf).collect(Collectors.toList());
				Collections.reverse(selectedRows);
				removeRows(selectedRows);
			}
		});
		authTableHeaderPanel.add(deleteRowButton);
		
		JButton addRowButton = new JButton(Captions.AUTH_CONTROL_BUTTON_ADD);
		addRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				addRow();
			}
		});
		authTableHeaderPanel.add(addRowButton);
		
	}

	private String[] convertAuthAccountDtoToObjectArray(AuthAccountDto dto) {
		return new String[] {dto.getUserId(), dto.getPassword(), dto.getRemark()};
	}

	private void loadRows() {
		authAccountDtos = Controller.getInstance().getAuthAccounts();
		authAccountDtos.forEach(authDto -> {
			tableModel.addRow(convertAuthAccountDtoToObjectArray(authDto));
		});
	}

	private void addRow() {
		AuthAccountDto authDto = new AuthAccountDto();
		Controller.getInstance().saveAuthAccount(authDto);
		authAccountDtos.add(authDto);
		tableModel.addRow(convertAuthAccountDtoToObjectArray(authDto));
	}

	private void removeRows(List<Integer> selectedRowsReversed) {
		Controller.getInstance().deleteAuthAccounts(selectedRowsReversed.stream()
				.map(selectedRow -> authAccountDtos.get(selectedRow))
				.collect(Collectors.toList()));

		selectedRowsReversed.forEach(selectedRow -> {
			authAccountDtos.remove(selectedRow.intValue());
			tableModel.removeRow(selectedRow);
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
		authAccountDtos = null;
	}

	public void refreshPanel() {
		clearRows();
		loadRows();
	}

}
