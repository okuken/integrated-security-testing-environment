package okuken.iste.view.option;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Frame;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Sizes;
import okuken.iste.dto.ProjectDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.ProjectLogic;
import okuken.iste.util.BurpUtil;

import javax.swing.JComboBox;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.awt.event.ActionEvent;

public class ProjectSelectorDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private final JPanel contentPanel = new JPanel();
	private JComboBox<ProjectDto> projectsComboBox;
	private JTextField newProjectNameTextField;

	/**
	 * Create the dialog.
	 */
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

			projectsComboBox.addItem(new ProjectDto());
			List<ProjectDto> projects = ProjectLogic.getInstance().loadProjects();
			Collections.reverse(projects);
			projects.stream().forEach(dto -> projectsComboBox.addItem(dto));

			projectsComboBox.setSelectedIndex(0);
			String lastSelectedProjectName = ConfigLogic.getInstance().getUserOptions().getLastSelectedProjectName();
			if(lastSelectedProjectName != null) {
				Optional<ProjectDto> lastSelectedProject = projects.stream().filter(projectDto -> lastSelectedProjectName.equals(projectDto.getName())).findFirst();
				if(lastSelectedProject.isPresent()) {
					projectsComboBox.setSelectedIndex(projects.indexOf(lastSelectedProject.get()) + 1);
				}
			}

			contentPanel.add(projectsComboBox, BorderLayout.NORTH);
		}
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			{
				JButton okButton = new JButton("OK");
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
				okButton.setActionCommand("OK");
				buttonPane.add(okButton);
				getRootPane().setDefaultButton(okButton);
			}
		}
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
