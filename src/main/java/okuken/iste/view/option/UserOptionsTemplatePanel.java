package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Sizes;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.UiUtil;
import okuken.iste.view.memo.MemoTextArea;
import okuken.iste.view.memo.ProjectMemoPanel;

import java.awt.BorderLayout;
import javax.swing.JButton;
import java.awt.GridLayout;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;
import java.awt.FlowLayout;

public class UserOptionsTemplatePanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JScrollPane messageMemoScrollPane;
	private JTextArea messageMemoTextArea;
	private JLabel messageMemoSaveMessageLabel;

	private JPanel projectMemoBodyPanel;
	private List<JTextArea> projectMemoTextAreas;
	private JLabel projectMemoSaveMessageLabel;

	public UserOptionsTemplatePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);
		
		
		JPanel messageMemoPanel = new JPanel();
		tabbedPane.addTab(Captions.TAB_MAIN, null, messageMemoPanel, null);
		messageMemoPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel messageMemoControlpanel = new JPanel();
		messageMemoPanel.add(messageMemoControlpanel, BorderLayout.NORTH);
		messageMemoControlpanel.setLayout(new BorderLayout(0, 0));
		
		JPanel messageMemoControlLeftpanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) messageMemoControlLeftpanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		messageMemoControlpanel.add(messageMemoControlLeftpanel, BorderLayout.WEST);
		
		JButton messageMemoSaveButton = new JButton(Captions.USER_OPTIONS_TEMPLATE_MEMO_BUTTON_SAVE);
		messageMemoSaveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				saveMessageMemoTemplates();
				UiUtil.showTemporaryMessage(messageMemoSaveMessageLabel, Captions.MESSAGE_SAVED);
			}
		});
		messageMemoControlLeftpanel.add(messageMemoSaveButton);
		
		messageMemoSaveMessageLabel = UiUtil.createTemporaryMessageArea();
		messageMemoControlLeftpanel.add(messageMemoSaveMessageLabel);
		
		JPanel messageMemoBodyPanel = new JPanel();
		messageMemoPanel.add(messageMemoBodyPanel, BorderLayout.CENTER);
		messageMemoBodyPanel.setLayout(new BorderLayout(0, 0));
		
		messageMemoTextArea = new JTextArea();
		messageMemoTextArea.setTabSize(Sizes.TAB_SIZE);
		UiUtil.addUndoRedoFeature(messageMemoTextArea);
		
		messageMemoScrollPane = new JScrollPane(messageMemoTextArea);
		messageMemoBodyPanel.add(messageMemoScrollPane, BorderLayout.CENTER);
		
		initMessageMemoBodyPanel();
		
		
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
		
		Controller.getInstance().setUserOptionsTemplatePanel(this);
	}

	public void refresh() {
		initMessageMemoBodyPanel();

		Arrays.stream(projectMemoBodyPanel.getComponents())
			.filter(component -> component instanceof JScrollPane)
			.forEach(component -> projectMemoBodyPanel.remove(component));
		initProjectMemoBodyPanel();
	}

	private void initMessageMemoBodyPanel() {
		messageMemoTextArea.setText(Optional.ofNullable(ConfigLogic.getInstance().getUserOptions().getMessageMemoTemplate()).orElse(""));
		SwingUtilities.invokeLater(() -> {
			UiUtil.initScrollBarPosition(messageMemoScrollPane);
		});
	}
	private void saveMessageMemoTemplates() {
		ConfigLogic.getInstance().saveMessageMemoTemplate(messageMemoTextArea.getText());
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
		if(templates == null || templates.isEmpty()) {
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
