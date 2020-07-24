package okuken.iste.view.header;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.MessageFilterDto;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;

import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JCheckBox;

public class MainHeaderPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JLabel projectNameLabel;
	private List<JCheckBox> progressCheckboxs;
	private JLabel rowCountLabel;

	public MainHeaderPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel leftPanel = new JPanel();
		add(leftPanel, BorderLayout.WEST);
		
		progressCheckboxs = Lists.newArrayList();
		Arrays.stream(SecurityTestingProgress.values()).forEach(progress -> {
			var progressCheckbox = new JCheckBox(progress.getCaption());
			progressCheckbox.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					applyMessageProgressFilter();
				}
			});
			progressCheckbox.setSelected(true);
			leftPanel.add(progressCheckbox);
			progressCheckboxs.add(progressCheckbox);
		});
		
		rowCountLabel = new JLabel("");
		leftPanel.add(rowCountLabel);
		
		JPanel centerPanel = new JPanel();
		projectNameLabel = new JLabel();
		refreshProjectName();
		centerPanel.add(projectNameLabel);
		add(centerPanel, BorderLayout.CENTER);
		
		JPanel rightPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) rightPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		
		JButton dockoutButton = new JButton(Captions.MAIN_HEADER_BUTTON_DOCKOUT);
		MainHeaderPanel that = this;
		dockoutButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(SwingUtilities.getWindowAncestor(that) == BurpUtil.getBurpSuiteJFrame()) {
					dockout();
				} else {
					dockin();
				}
			}
		});
		
		JButton initColumnWidthButton = new JButton(Captions.MAIN_HEADER_BUTTON_INIT_COLUMN_WIDTH);
		initColumnWidthButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().initSizeRatioOfParts();
			}
		});
		
		rightPanel.add(initColumnWidthButton);
		rightPanel.add(dockoutButton);
		add(rightPanel, BorderLayout.EAST);

		Controller.getInstance().setMainHeaderPanel(this);
	}

	private void dockout() {
		JFrame burpSuiteFrame = BurpUtil.getBurpSuiteJFrame();
		SwingUtilities.invokeLater(() -> {
			JFrame dockoutFrame = new JFrame();
			Controller.getInstance().setDockoutFrame(dockoutFrame);

			dockoutFrame.setTitle(Captions.TAB_SUITE);
			dockoutFrame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
			dockoutFrame.setBounds(burpSuiteFrame.getBounds());
			dockoutFrame.setContentPane(Controller.getInstance().getMainPanel());
			dockoutFrame.setLocationRelativeTo(burpSuiteFrame);
			dockoutFrame.setVisible(true);
		});
	}

	private void dockin() {
		Controller controller = Controller.getInstance();
		controller.getMainTabbedPane().insertTab(Captions.TAB_MAIN, null, controller.getMainPanel(), null, 0);
		controller.getMainTabbedPane().setSelectedIndex(0);
		controller.disposeDockoutFrame();
	}

	public void applyMessageProgressFilter() {
		var dto = new MessageFilterDto();
		dto.setProgresses(progressCheckboxs.stream()
			.filter(progressCheckbox -> progressCheckbox.isSelected())
			.map(progressCheckbox -> SecurityTestingProgress.getByCaption(progressCheckbox.getText()))
			.collect(Collectors.toList()));

		int rowCount = Controller.getInstance().applyMessageFilter(dto);
		setRowCount(rowCount);
	}

	private void setRowCount(int rowCount) {
		rowCountLabel.setText(String.format(" [%d] ", rowCount));
	}

	public void refreshProjectName() {
		projectNameLabel.setText(ConfigLogic.getInstance().getProcessOptions().getProjectDto().getName());
	}

}
