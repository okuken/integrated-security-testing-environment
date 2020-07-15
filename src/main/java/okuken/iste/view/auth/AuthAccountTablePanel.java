package okuken.iste.view.auth;

import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JScrollPane;
import javax.swing.table.DefaultTableModel;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.logic.AuthLogic;
import okuken.iste.util.BurpUtil;

import java.awt.BorderLayout;
import javax.swing.JButton;
import javax.swing.JOptionPane;

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

public class AuthAccountTablePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTable table;

	private static final int COLNUM_USER_ID = 0;
	private static final int COLNUM_PASSWORD = 1;
	private static final int COLNUM_REMARK = 2;

	private DefaultTableModel tableModel;

	private List<AuthAccountDto> authAccountDtos;

	@SuppressWarnings("serial")
	public AuthAccountTablePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
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
				switch (columnIndex) {
					case COLNUM_USER_ID:
						if(val.equals(dto.getUserId())) {
							return;
						}
						dto.setUserId((String)val);
						break;
					case COLNUM_PASSWORD:
						if(val.equals(dto.getPassword())) {
							return;
						}
						dto.setPassword((String)val);
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
			}
		});
		table.getColumnModel().getColumn(COLNUM_USER_ID).setPreferredWidth(100);
		table.getColumnModel().getColumn(COLNUM_PASSWORD).setPreferredWidth(100);
		table.getColumnModel().getColumn(COLNUM_REMARK).setPreferredWidth(300);
		scrollPane.setViewportView(table);
		
		SwingUtilities.invokeLater(() -> { // run after IBurpExtenderCallbacks#customizeUiComponent().
			table.setBorder(new LineBorder(Colors.TABLE_BORDER));
		});
		
		tableModel = (DefaultTableModel) table.getModel();
		
		JPanel authTableHeaderPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) authTableHeaderPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(authTableHeaderPanel, BorderLayout.NORTH);
		
		JButton addRowButton = new JButton(Captions.AUTH_CONTROL_BUTTON_ADD);
		addRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				AuthAccountDto authDto = showInputDialog();
				if(authDto == null) {
					return;
				}

				Controller.getInstance().saveAuthAccount(authDto);
				tableModel.addRow(convertAuthAccountDtoToObjectArray(authDto));
			}
		});
		authTableHeaderPanel.add(addRowButton);
		
		JButton deleteRowButton = new JButton(Captions.AUTH_CONTROL_BUTTON_DELETE);
		deleteRowButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				List<Integer> selectedRows = Arrays.stream(table.getSelectedRows()).mapToObj(Integer::valueOf).collect(Collectors.toList());
				Collections.reverse(selectedRows);

				Controller.getInstance().deleteAuthAccounts(selectedRows.stream()
						.map(selectedRow -> authAccountDtos.get(selectedRow))
						.collect(Collectors.toList()));

				selectedRows.forEach(selectedRow -> {
					tableModel.removeRow(selectedRow);
				});
			}
		});
		authTableHeaderPanel.add(deleteRowButton);
		
	}

	private String[] convertAuthAccountDtoToObjectArray(AuthAccountDto dto) {
		return new String[] {dto.getUserId(), dto.getPassword(), dto.getRemark()};
	}

	private AuthAccountDto showInputDialog() {
		JTextField userIdTextField = new JTextField();
		JTextField passwordTextField = new JTextField();
		JTextField remarkTextField = new JTextField();

		//TODO: validation
		int option = JOptionPane.showConfirmDialog(BurpUtil.getBurpSuiteJFrame(), new Object[] {
				Captions.AUTH_TABLE_FIELD_USER_ID, userIdTextField,
				Captions.AUTH_TABLE_FIELD_PASSWORD, passwordTextField,
				Captions.AUTH_TABLE_FIELD_REMARK, remarkTextField,
		}, "", JOptionPane.OK_CANCEL_OPTION);

		switch (option) {
		case JOptionPane.OK_OPTION:
			AuthAccountDto authDto = new AuthAccountDto();
			authDto.setUserId(userIdTextField.getText());
			authDto.setPassword(passwordTextField.getText());
			authDto.setRemark(remarkTextField.getText());
			return authDto;
		default:
			return null;
		}
	}

	private void loadRows() {
		authAccountDtos = Controller.getInstance().getAuthAccounts();
		authAccountDtos.forEach(authDto -> {
			tableModel.addRow(convertAuthAccountDtoToObjectArray(authDto));
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
