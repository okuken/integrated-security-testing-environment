package okuken.iste.view.option;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import okuken.iste.consts.Captions;
import okuken.iste.dto.ProjectDto;
import okuken.iste.logic.ProjectLogic;

import javax.swing.JComboBox;
import javax.swing.JTextField;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.awt.event.ActionEvent;

public class ProjectSelectorDialog extends JDialog {

	private static final long serialVersionUID = 1L;

	private final JPanel contentPanel = new JPanel();
	private JComboBox<ProjectDto> projectsComboBox;
	private JTextField newProjectNameTextField;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		try {
			ProjectSelectorDialog dialog = new ProjectSelectorDialog();
			dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Create the dialog.
	 */
	public ProjectSelectorDialog() {
		setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
		setModal(true);
		setTitle(Captions.MESSAGE_SELECT_PROJECT);
		setBounds(100, 100, 450, 150);
		getContentPane().setLayout(new BorderLayout());
		contentPanel.setLayout(new FlowLayout());
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		{
			projectsComboBox = new JComboBox<ProjectDto>();
			projectsComboBox.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					if(newProjectNameTextField == null) {
						return;
					}

					if(projectsComboBox.getSelectedIndex() == 0) {
						newProjectNameTextField.setEnabled(true);
					} else {
						newProjectNameTextField.setEnabled(false);
					}
				}
			});
			projectsComboBox.setMaximumRowCount(1000);

			projectsComboBox.addItem(new ProjectDto());
			ProjectLogic.getInstance().loadProjects().stream().forEach(dto -> projectsComboBox.addItem(dto));

			projectsComboBox.setSelectedIndex(0);
			contentPanel.add(projectsComboBox);
		}
		{
			newProjectNameTextField = new JTextField();
			newProjectNameTextField.setText(new SimpleDateFormat("yyyyMMdd_HHmmss").format(Calendar.getInstance().getTime()));
			contentPanel.add(newProjectNameTextField);
			newProjectNameTextField.setColumns(20);
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

	public ProjectDto getSelectedProject() {
		return projectsComboBox.getItemAt(projectsComboBox.getSelectedIndex());
	}

}
