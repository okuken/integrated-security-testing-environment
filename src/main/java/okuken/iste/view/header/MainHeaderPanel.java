package okuken.iste.view.header;

import javax.swing.JPanel;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageFilterDto;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

import java.awt.FlowLayout;

import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class MainHeaderPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JLabel projectNameLabel;
	private List<JCheckBox> progressCheckboxs;
	private JLabel rowCountLabel;

	private JButton dockoutButton;
	private JTextField searchTextField;

	public MainHeaderPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel leftPanel = new JPanel();
		add(leftPanel, BorderLayout.WEST);
		
		progressCheckboxs = Lists.newArrayList();
		Arrays.stream(SecurityTestingProgress.values()).forEach(progress -> {
			var progressCheckbox = new JCheckBox(progress.getCaption());
			progressCheckbox.setToolTipText(Captions.MAIN_HEADER_CHECKBOX_FILTER_PROGRESS_TT);
			progressCheckbox.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					applyMessageFilter();
				}
			});
			progressCheckbox.setSelected(true);
			leftPanel.add(progressCheckbox);
			progressCheckboxs.add(progressCheckbox);
		});
		
		searchTextField = new JTextField();
		searchTextField.setToolTipText(Captions.MAIN_HEADER_INPUT_FILTER_TERM_TT);
		leftPanel.add(searchTextField);
		searchTextField.setColumns(20);
		searchTextField.getDocument().addDocumentListener(new DocumentListener() {
			public void removeUpdate(DocumentEvent e) {apply();}
			public void insertUpdate(DocumentEvent e) {apply();}
			public void changedUpdate(DocumentEvent e) {apply();}
			private void apply() {
				applyMessageFilter();
			}
		});
		
		rowCountLabel = new JLabel("");
		leftPanel.add(rowCountLabel);
		
		JPanel centerPanel = new JPanel();
		projectNameLabel = new JLabel();
		refreshProjectName();
		centerPanel.add(projectNameLabel);
		add(centerPanel, BorderLayout.CENTER);
		
		JButton changeProjectButton = new JButton(Captions.MAIN_HEADER_BUTTON_CHANGE_PROJECT);
		changeProjectButton.setToolTipText(Captions.MAIN_HEADER_BUTTON_CHANGE_PROJECT_TT);
		changeProjectButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().changeProject(false);
			}
		});
		centerPanel.add(changeProjectButton);
		
		JPanel rightPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) rightPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		
		JButton initColumnWidthButton = new JButton(Captions.MAIN_HEADER_BUTTON_INIT_COLUMN_WIDTH);
		initColumnWidthButton.setToolTipText(Captions.MAIN_HEADER_BUTTON_INIT_COLUMN_WIDTH_TT);
		initColumnWidthButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().initSizeRatioOfParts();
			}
		});
		rightPanel.add(initColumnWidthButton);
		
		dockoutButton = new JButton();
		rightPanel.add(dockoutButton);
		
		add(rightPanel, BorderLayout.EAST);

		Controller.getInstance().setMainHeaderPanel(this);
	}

	public void applyMessageFilter() {
		int rowCount = Controller.getInstance().applyMessageFilter(createMessageFilterDto());
		setRowCount(rowCount);
	}

	private MessageFilterDto createMessageFilterDto() {
		var ret = new MessageFilterDto();
		ret.setProgresses(progressCheckboxs.stream()
			.filter(progressCheckbox -> progressCheckbox.isSelected())
			.map(progressCheckbox -> SecurityTestingProgress.getByCaption(progressCheckbox.getText()))
			.collect(Collectors.toList()));

		ret.setSearchWord(searchTextField.getText());

		return ret;
	}

	public MessageFilterDto getMessageFilterDto() {
		return createMessageFilterDto();
	}

	public void focusOnSearch() {
		UiUtil.focus(searchTextField);
		searchTextField.selectAll();
	}

	private void setRowCount(int rowCount) {
		rowCountLabel.setText(String.format(" [%d] ", rowCount));
	}

	public void refreshProjectName() {
		var projectName = ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName();
		projectNameLabel.setText(projectName);

		var burpProjectName = BurpUtil.getBurpSuiteProjectName();
		if(burpProjectName != null && !burpProjectName.equals(projectName)) {
			projectNameLabel.setForeground(Colors.CHARACTER_ALERT);
			projectNameLabel.setToolTipText(Captions.MAIN_HEADER_ALERT_PROJECT_TT);
		} else {
			projectNameLabel.setForeground(BurpUtil.getDefaultForegroundColor());
			projectNameLabel.setToolTipText(null);
		}
	}

	public JButton getDockoutButton() {
		return dockoutButton;
	}

}
