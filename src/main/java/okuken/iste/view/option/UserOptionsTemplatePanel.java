package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.UiUtil;
import okuken.iste.view.memo.MemoTextArea;
import okuken.iste.view.memo.ProjectMemoPanel;

import java.awt.BorderLayout;
import javax.swing.JButton;
import java.awt.GridLayout;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;

public class UserOptionsTemplatePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JPanel projectMemoBodyPanel;
	private List<JTextArea> projectMemoTextAreas;

	private JLabel projectMemoSaveMessageLabel;

	public UserOptionsTemplatePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);
		
		JPanel projectMemoPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_MEMO, null, projectMemoPanel, null);
		projectMemoPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel projectMemoControlPanel = new JPanel();
		projectMemoControlPanel.setLayout(new BorderLayout(0, 0));
		projectMemoPanel.add(projectMemoControlPanel, BorderLayout.NORTH);
		
		JPanel projectMemoControlLeftPanel = new JPanel();
		projectMemoControlPanel.add(projectMemoControlLeftPanel, BorderLayout.WEST);
		
		JButton projectMemoSaveButton = new JButton(Captions.USER_OPTIONS_TEMPLATE_MEMO_BUTTON_SAVE);
		projectMemoSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				saveProjectMemoTemplates();
				UiUtil.showTemporaryMessage(projectMemoSaveMessageLabel, Captions.MESSAGE_SAVED);
			}
		});
		projectMemoControlLeftPanel.add(projectMemoSaveButton);
		
		projectMemoSaveMessageLabel = UiUtil.createTemporaryMessageArea();
		projectMemoControlLeftPanel.add(projectMemoSaveMessageLabel);
		
		projectMemoBodyPanel = new JPanel();
		projectMemoPanel.add(projectMemoBodyPanel, BorderLayout.CENTER);
		projectMemoBodyPanel.setLayout(new GridLayout(0, 2, 0, 0));
		initProjectMemoBodyPanel();

	}

	private void initProjectMemoBodyPanel() {
		projectMemoTextAreas = getProjectMemoTemplates().stream()
			.map(projectMemoTemplate -> new MemoTextArea(projectMemoTemplate, null))
			.collect(Collectors.toList());

		projectMemoTextAreas.forEach(projectMemoTextArea -> {
			var scrollPane = new JScrollPane();
			projectMemoBodyPanel.add(scrollPane);
			scrollPane.setViewportView(projectMemoTextArea);

			SwingUtilities.invokeLater(() -> {
				UiUtil.initScrollBarPosition(scrollPane);
			});
		});
	}

	private List<String> getProjectMemoTemplates() {
		var templates = ConfigLogic.getInstance().getUserOptions().getProjectMemoTemplates();
		if(templates == null) {
			return IntStream.range(0, ProjectMemoPanel.PROJECT_MEMO_COUNT).mapToObj(i -> "").collect(Collectors.toList());
		}
		return templates;
	}

	private void saveProjectMemoTemplates() {
		ConfigLogic.getInstance().saveProjectMemoTemplates(projectMemoTextAreas.stream()
				.map(JTextArea::getText)
				.collect(Collectors.toList()));
	}

}
