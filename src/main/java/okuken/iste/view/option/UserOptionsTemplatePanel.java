package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.view.memo.ProjectMemoPanel;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import javax.swing.JButton;
import java.awt.GridLayout;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class UserOptionsTemplatePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JPanel projectMemoBodyPanel;
	private List<JTextArea> projectMemoTextAreas = Lists.newArrayList();

	public UserOptionsTemplatePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);
		
		JPanel projectMemoPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_MEMO, null, projectMemoPanel, null);
		projectMemoPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel projectMemoHeaderPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) projectMemoHeaderPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		projectMemoPanel.add(projectMemoHeaderPanel, BorderLayout.NORTH);
		
		JButton projectMemoSaveButton = new JButton(Captions.USER_OPTIONS_TEMPLATE_MEMO_BUTTON_SAVE);
		projectMemoSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				saveProjectMemoTemplates();
			}
		});
		projectMemoHeaderPanel.add(projectMemoSaveButton);
		
		projectMemoBodyPanel = new JPanel();
		projectMemoPanel.add(projectMemoBodyPanel, BorderLayout.CENTER);
		projectMemoBodyPanel.setLayout(new GridLayout(0, 2, 0, 0));
		initProjectMemoBodyPanel();

	}

	private void initProjectMemoBodyPanel() {
		IntStream.range(0, ProjectMemoPanel.PROJECT_MEMO_COUNT).forEach(i -> {
			var scrollPane = new JScrollPane();
			projectMemoBodyPanel.add(scrollPane);
			var textArea = new JTextArea();
			scrollPane.setViewportView(textArea);
			SwingUtilities.invokeLater(() -> {
				JScrollBar scrollBar = scrollPane.getVerticalScrollBar();
				scrollBar.setValue(scrollBar.getMinimum());
			});
			
			projectMemoTextAreas.add(textArea);
		});

		loadProjectMemoTemplates();
	}

	private void loadProjectMemoTemplates() {
		var templates = ConfigLogic.getInstance().getUserOptions().getProjectMemoTemplates();
		if(templates == null) {
			return;
		}

		IntStream.range(0, projectMemoTextAreas.size()).forEach(i -> {
			if(i < templates.size()) {
				projectMemoTextAreas.get(i).setText(templates.get(i));
			}
		});
	}

	private void saveProjectMemoTemplates() {
		ConfigLogic.getInstance().saveProjectMemoTemplates(projectMemoTextAreas.stream()
				.map(JTextArea::getText)
				.collect(Collectors.toList()));
	}

}
