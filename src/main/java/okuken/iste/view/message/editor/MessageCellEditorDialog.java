package okuken.iste.view.message.editor;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Optional;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;
import okuken.iste.view.message.table.MessageTableColumn;
import javax.swing.JRadioButton;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.JLabel;
import javax.swing.SwingConstants;

public class MessageCellEditorDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private static final String DEFAULT_NUMBERING_FORMAT = "%d. %s";

	private List<MessageDto> messages;
	private MessageTableColumn columnType;

	private final JPanel contentPanel = new JPanel();

	private ButtonGroup radioButtonGroup;
	private JRadioButton inputRadioButton;
	private JRadioButton replaceRadioButton;
	private JRadioButton numberingRadioButton;

	private JTextField inputTextField;
	private JTextField replaceFromTextField;
	private JTextField replaceToTextField;
	private JTextField numberingFormatTextField;
	private JTextField numberingFromTextField;

	private JLabel errorMsgLabel;

	public MessageCellEditorDialog(Frame owner, List<MessageDto> messages, MessageTableColumn columnType) {
		super(owner);
		this.messages = messages;
		this.columnType = columnType;
		
		setModal(true);
		setTitle(columnType.getCaption());
		
		setBounds(100, 100, 500, 170);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		GridBagLayout gbl_contentPanel = new GridBagLayout();
		gbl_contentPanel.columnWidths = new int[]{165, 105, 0, 0};
		gbl_contentPanel.rowHeights = new int[]{21, 0, 0, 0};
		gbl_contentPanel.columnWeights = new double[]{0.0, 1.0, 1.0, Double.MIN_VALUE};
		gbl_contentPanel.rowWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		contentPanel.setLayout(gbl_contentPanel);
		radioButtonGroup = new ButtonGroup();
		{
			inputRadioButton = new JRadioButton(Captions.TABLE_CELL_EDITOR_INPUT);
			inputRadioButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					refreshComponents();
				}
			});
			radioButtonGroup.add(inputRadioButton);
			GridBagConstraints gbc_inputRadioButton = new GridBagConstraints();
			gbc_inputRadioButton.insets = new Insets(0, 0, 5, 5);
			gbc_inputRadioButton.anchor = GridBagConstraints.NORTHWEST;
			gbc_inputRadioButton.gridx = 0;
			gbc_inputRadioButton.gridy = 0;
			contentPanel.add(inputRadioButton, gbc_inputRadioButton);
		}
		{
			inputTextField = new JTextField();
			GridBagConstraints gbc_inputTextField = new GridBagConstraints();
			gbc_inputTextField.insets = new Insets(0, 0, 5, 5);
			gbc_inputTextField.fill = GridBagConstraints.HORIZONTAL;
			gbc_inputTextField.gridx = 1;
			gbc_inputTextField.gridy = 0;
			contentPanel.add(inputTextField, gbc_inputTextField);
			inputTextField.setColumns(10);
		}
		{
			replaceRadioButton = new JRadioButton(Captions.TABLE_CELL_EDITOR_REPLACE);
			replaceRadioButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					refreshComponents();
				}
			});
			radioButtonGroup.add(replaceRadioButton);
			GridBagConstraints gbc_replaceRadioButton = new GridBagConstraints();
			gbc_replaceRadioButton.anchor = GridBagConstraints.WEST;
			gbc_replaceRadioButton.insets = new Insets(0, 0, 5, 5);
			gbc_replaceRadioButton.gridx = 0;
			gbc_replaceRadioButton.gridy = 1;
			contentPanel.add(replaceRadioButton, gbc_replaceRadioButton);
		}
		{
			replaceFromTextField = new JTextField();
			GridBagConstraints gbc_replaceFromTextField = new GridBagConstraints();
			gbc_replaceFromTextField.insets = new Insets(0, 0, 5, 5);
			gbc_replaceFromTextField.fill = GridBagConstraints.HORIZONTAL;
			gbc_replaceFromTextField.gridx = 1;
			gbc_replaceFromTextField.gridy = 1;
			contentPanel.add(replaceFromTextField, gbc_replaceFromTextField);
			replaceFromTextField.setColumns(10);
		}
		{
			replaceToTextField = new JTextField();
			GridBagConstraints gbc_replaceToTextField = new GridBagConstraints();
			gbc_replaceToTextField.insets = new Insets(0, 0, 5, 0);
			gbc_replaceToTextField.fill = GridBagConstraints.HORIZONTAL;
			gbc_replaceToTextField.gridx = 2;
			gbc_replaceToTextField.gridy = 1;
			contentPanel.add(replaceToTextField, gbc_replaceToTextField);
			replaceToTextField.setColumns(10);
		}
		{
			numberingRadioButton = new JRadioButton(Captions.TABLE_CELL_EDITOR_NUMBERING);
			numberingRadioButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					refreshComponents();
				}
			});
			radioButtonGroup.add(numberingRadioButton);
			GridBagConstraints gbc_numberingRadioButton = new GridBagConstraints();
			gbc_numberingRadioButton.anchor = GridBagConstraints.WEST;
			gbc_numberingRadioButton.insets = new Insets(0, 0, 0, 5);
			gbc_numberingRadioButton.gridx = 0;
			gbc_numberingRadioButton.gridy = 2;
			contentPanel.add(numberingRadioButton, gbc_numberingRadioButton);
		}
		{
			numberingFormatTextField = new JTextField();
			GridBagConstraints gbc_numberingFormatTextField = new GridBagConstraints();
			gbc_numberingFormatTextField.insets = new Insets(0, 0, 0, 5);
			gbc_numberingFormatTextField.fill = GridBagConstraints.HORIZONTAL;
			gbc_numberingFormatTextField.gridx = 1;
			gbc_numberingFormatTextField.gridy = 2;
			contentPanel.add(numberingFormatTextField, gbc_numberingFormatTextField);
			numberingFormatTextField.setColumns(10);
		}
		{
			JPanel numberingFromPanel = new JPanel();
			GridBagConstraints gbc_numberingFromPanel = new GridBagConstraints();
			gbc_numberingFromPanel.fill = GridBagConstraints.BOTH;
			gbc_numberingFromPanel.gridx = 2;
			gbc_numberingFromPanel.gridy = 2;
			contentPanel.add(numberingFromPanel, gbc_numberingFromPanel);
			numberingFromPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
			{
				JLabel numberingFromLabel = new JLabel(Captions.TABLE_CELL_EDITOR_NUMBERING_FROM);
				numberingFromPanel.add(numberingFromLabel);
			}
			{
				numberingFromTextField = new JTextField();
				numberingFromTextField.setHorizontalAlignment(SwingConstants.RIGHT);
				numberingFromPanel.add(numberingFromTextField);
				numberingFromTextField.setColumns(2);
			}
		}
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				errorMsgLabel = new JLabel(" ");
				errorMsgLabel.setForeground(Colors.CHARACTER_ALERT);
				buttonPane.add(errorMsgLabel);
				
				JButton okButton = new JButton(Captions.OK);
				okButton.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						if(save()) {
							dispose();
						}
					}
				});
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
				
				JButton cancelButton = new JButton(Captions.CANCEL);
				cancelButton.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						dispose();
					}
				});
				buttonPane.add(cancelButton);
			}
		}
		getRootPane().registerKeyboardAction(e -> {dispose();}, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

		init();
	}

	private void init() {
		inputRadioButton.setSelected(true);
		inputTextField.setText(getSelectedTableCellValue().toString());

		numberingFormatTextField.setText(DEFAULT_NUMBERING_FORMAT);
		numberingFromTextField.setText("1");

		refreshComponents();
	}
	private Object getSelectedTableCellValue() {
		try {
			return Optional.ofNullable(columnType.getGetter().invoke(messages.get(0))).orElse("");
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}

	private void refreshComponents() {
		inputTextField.setEnabled(inputRadioButton.isSelected());

		replaceFromTextField.setEnabled(replaceRadioButton.isSelected());
		replaceToTextField.setEnabled(replaceRadioButton.isSelected());
		if(replaceRadioButton.isSelected()) {
			replaceFromTextField.requestFocusInWindow();
		}

		numberingFormatTextField.setEnabled(numberingRadioButton.isSelected());
		numberingFromTextField.setEnabled(numberingRadioButton.isSelected());
		if(numberingRadioButton.isSelected()) {
			numberingFormatTextField.requestFocusInWindow();
		}
	}

	private boolean validateInputs() {
		if(replaceRadioButton.isSelected()) {
			if(StringUtils.isEmpty(replaceFromTextField.getText())) {
				showErrorMsg("replaceFromText is required.");
				return false;
			}
			return true;
		}
		if(numberingRadioButton.isSelected()) {
			var numberingFormat = numberingFormatTextField.getText();
			if(StringUtils.isEmpty(numberingFormat)) {
				showErrorMsg("numberingFormat is required.");
				return false;
			}
			if(!numberingFormat.contains("%s")) {
				showErrorMsg("numberingFormat must include %s.");
				return false;
			}
			return true;
		}

		return true;
	}

	private boolean save() {
		if(!validateInputs()) {
			return false;
		}

		try {
			int number = Integer.parseInt(numberingFromTextField.getText());
			for(var message: messages) {
				columnType.getSetter().invoke(message, makeApplyValue(message, number));
				Controller.getInstance().updateMessage(message, false);
				number++;
			};
			Controller.getInstance().applyMessageFilter();
			return true;
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			showErrorMsg(e.getMessage());
			throw new RuntimeException(e);
		}
	}
	private String makeApplyValue(MessageDto message, int number) {
		if(inputRadioButton.isSelected()) {
			return inputTextField.getText();
		}

		try {
			var currentValue = (String)Optional.ofNullable(columnType.getGetter().invoke(message)).orElse("");
			if(replaceRadioButton.isSelected()) {
				return currentValue.replaceAll(replaceFromTextField.getText(), replaceToTextField.getText());
			}
			if(numberingRadioButton.isSelected()) {
				var numberingFormat = numberingFormatTextField.getText();
				numberingFormat = numberingFormat.replaceAll("%s", currentValue); //consider order...
				return String.format(numberingFormat, number);
			}
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}
		throw new IllegalArgumentException("must select edit type.");
	}

	private void showErrorMsg(String errorMsg) {
		errorMsgLabel.setText(errorMsg);
	}

}
