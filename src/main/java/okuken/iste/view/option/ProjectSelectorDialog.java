package okuken.iste.view.option;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Frame;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.dto.ProjectDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.FileUtil;

import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.awt.event.ActionEvent;

public class ProjectSelectorDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private final JPanel contentPanel = new JPanel();
	private JComboBox<ProjectDto> projectsComboBox;
	private JTextField newProjectNameTextField;

	private String burpProjectName;

	/**
	 * Create the dialog.
	 */
	@SuppressWarnings("serial")
	public ProjectSelectorDialog(Frame owner) {
		super(owner);

		setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
		setModal(true);
		setTitle(Captions.MESSAGE_SELECT_PROJECT);
		setBounds(100, 100, 400, 136);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(new BorderLayout(0, 0));
		{
			newProjectNameTextField = new JTextField();
			contentPanel.add(newProjectNameTextField, BorderLayout.CENTER);
			newProjectNameTextField.setColumns(20);
		}
		{
			projectsComboBox = new JComboBox<ProjectDto>();
			projectsComboBox.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					if(projectsComboBox.getSelectedIndex() == 0) {
						newProjectNameTextField.setEnabled(true);
						newProjectNameTextField.setText(createDefaultNewProjectName());
					} else {
						newProjectNameTextField.setEnabled(false);
						newProjectNameTextField.setText("");
					}
				}
			});
			projectsComboBox.setMaximumRowCount(Sizes.MAX_ROW_COUNT_COMBOBOX);

			burpProjectName = BurpUtil.getBurpSuiteProjectName();
			if(burpProjectName != null) {
				SwingUtilities.invokeLater(() -> {
					projectsComboBox.setRenderer(new DefaultListCellRenderer() {
						@Override
						public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
							var component =  super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
							if (burpProjectName.equals(((ProjectDto)value).getName())) {
								component.setForeground(Colors.COMBOBOX_FOREGROUND_HIGHLIGHT);
							}
							return component;
						}
					});
				});
			}

			loadProjects(true);

			contentPanel.add(projectsComboBox, BorderLayout.NORTH);
		}
		{
			JPanel buttonPane = new JPanel();
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			buttonPane.setLayout(new BorderLayout(0, 0));
			{
				JPanel buttonLeftPanel = new JPanel();
				buttonPane.add(buttonLeftPanel, BorderLayout.WEST);
				{
					JButton changeDbButton = new JButton(Captions.CHANGE_DATABASE);
					changeDbButton.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							changeDatabase();
						}
					});
					buttonLeftPanel.add(changeDbButton);
				}
			}
			{
				{
					JPanel buttonRightPanel = new JPanel();
					buttonPane.add(buttonRightPanel, BorderLayout.EAST);
					JButton okButton = new JButton(Captions.OK);
					buttonRightPanel.add(okButton);
					okButton.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							int selectedIndex = projectsComboBox.getSelectedIndex();
							if(selectedIndex == 0) { //TODO: validation
								ProjectDto newDto = projectsComboBox.getItemAt(projectsComboBox.getSelectedIndex());
								newDto.setName(newProjectNameTextField.getText());
								newDto.setExplanation("");//TODO
							}
							dispose();
						}
					});
					getRootPane().setDefaultButton(okButton);
				}
			}
		}
	}

	private void loadProjects(boolean init) {
		projectsComboBox.removeAllItems();

		projectsComboBox.addItem(new ProjectDto());
		List<ProjectDto> projects = ProjectLogic.getInstance().loadProjects();
		Collections.reverse(projects);
		projects.stream().forEach(dto -> projectsComboBox.addItem(dto));

		projectsComboBox.setSelectedIndex(0);
		selectProjectIfExist(ConfigLogic.getInstance().getUserOptions().getLastSelectedProjectName(), projects);
		if(!init) {
			selectProjectIfExist(burpProjectName, projects);
		}
	}
	private void selectProjectIfExist(String selectProjectName, List<ProjectDto> projects) {
		if(selectProjectName == null) {
			return;
		}
		var selectProject = projects.stream().filter(projectDto -> selectProjectName.equals(projectDto.getName())).findFirst();
		if(selectProject.isPresent()) {
			projectsComboBox.setSelectedIndex(projects.indexOf(selectProject.get()) + 1);
		}
	}

	private void changeDatabase() {
		var currentDbFilePath = ConfigLogic.getInstance().getUserOptions().getDbFilePath();

		JFileChooser fileChooser = FileUtil.createSingleFileChooser(Captions.MESSAGE_CHOOSE_DB_FILE, currentDbFilePath);
		if (fileChooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
			return;
		}

		var newDbFilePath = fileChooser.getSelectedFile().getAbsolutePath();
		if(StringUtils.equals(currentDbFilePath, newDbFilePath)) {
			return;
		}

		Controller.getInstance().changeDatabaseOnly(newDbFilePath);
		loadProjects(false);
	}

	private String createDefaultNewProjectName() {
		var burpSuiteProjectName = BurpUtil.getBurpSuiteProjectName();
		if(burpSuiteProjectName != null) {
			return burpSuiteProjectName;
		}
		return new SimpleDateFormat("yyyyMMdd_HHmmss").format(Calendar.getInstance().getTime()) + "_projectname";
	}

	public void setSelectNewProject() {
		projectsComboBox.setSelectedIndex(0);
	}

	public ProjectDto getSelectedProject() {
		return projectsComboBox.getItemAt(projectsComboBox.getSelectedIndex());
	}

}
