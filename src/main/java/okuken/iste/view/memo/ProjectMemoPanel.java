package okuken.iste.view.memo;

import javax.swing.JPanel;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.AbstractButton;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.ProjectMemoDto;
import okuken.iste.logic.MemoLogic;
import okuken.iste.util.UiUtil;
import okuken.iste.view.AbstractDockoutableTabPanel;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.List;
import java.util.stream.Collectors;
import java.awt.GridLayout;

public class ProjectMemoPanel extends AbstractDockoutableTabPanel {

	private static final long serialVersionUID = 1L;

	public static final int PROJECT_MEMO_COUNT = 4;

	private JButton dockoutButton;
	private JPanel memoPanel;

	private List<MemoTextArea> memoTextAreas;

	public ProjectMemoPanel() {
		setLayout(new BorderLayout(0, 0));
		
		memoPanel = new JPanel();
		add(memoPanel, BorderLayout.CENTER);
		memoPanel.setLayout(new GridLayout(0, 2, 0, 0));
		
		JPanel headerPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) headerPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		add(headerPanel, BorderLayout.NORTH);
		
		JButton wrapButton = new JButton(Captions.PROJECT_MEMO_BUTTON_WRAP);
		wrapButton.setToolTipText(Captions.PROJECT_MEMO_BUTTON_WRAP_TT);
		wrapButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				memoTextAreas.forEach(memoTextArea -> {
					memoTextArea.setLineWrap(!memoTextArea.getLineWrap());
				});
			}
		});
		headerPanel.add(wrapButton);
		
		dockoutButton = new JButton();
		headerPanel.add(dockoutButton);
		setupDockout();

	}

	private void load() {
		var projectMemos = Controller.getInstance().getProjectMemos();
		var projectMemosSize = projectMemos.size();
		for(int i = 0; i < PROJECT_MEMO_COUNT - projectMemosSize; i++) {
			var projectMemoDto = new ProjectMemoDto();
			MemoLogic.getInstance().saveProjectMemo(projectMemoDto); //[CAUTION]insert empty for remain order
			projectMemos.add(projectMemoDto);
		}

		memoTextAreas = projectMemos.stream().map(projectMemoDto -> new MemoTextArea(
					projectMemoDto.getMemo(),
					memo -> {
						projectMemoDto.setMemo(memo);
						MemoLogic.getInstance().saveProjectMemo(projectMemoDto);
					})).collect(Collectors.toList());

		memoTextAreas.forEach(memoTextArea -> {
			JScrollPane scrollPane = new JScrollPane();
			memoPanel.add(scrollPane);
			scrollPane.setViewportView(memoTextArea);

			SwingUtilities.invokeLater(() -> {
				UiUtil.initScrollBarPosition(scrollPane);
			});
		});
	}

	public void refreshPanel() {
		memoPanel.removeAll();
		load();
	}

	@Override
	protected AbstractButton getDockoutButton() {
		return dockoutButton;
	}
	@Override
	protected String getTabName() {
		return Captions.TAB_MEMO;
	}
	@Override
	protected int getTabIndex() {
		return 1; //TODO: consider other dockout
	}

}
