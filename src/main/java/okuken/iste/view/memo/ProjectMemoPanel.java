package okuken.iste.view.memo;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.undo.UndoManager;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.util.UiUtil;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

public class ProjectMemoPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JTextArea memoTextArea;

	private boolean memoChanged;
	private UndoManager undoManager;

	public ProjectMemoPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel memoPanel = new JPanel();
		add(memoPanel, BorderLayout.CENTER);
		memoPanel.setLayout(new BorderLayout(0, 0));
		
		JScrollPane scrollPane = new JScrollPane();
		memoPanel.add(scrollPane);
		
		memoTextArea = new JTextArea();
		memoTextArea.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				setMemoChanged();
			}
			@Override
			public void insertUpdate(DocumentEvent e) {
				setMemoChanged();
			}
			@Override
			public void changedUpdate(DocumentEvent e) {
				setMemoChanged();
			}
			private void setMemoChanged() {
				memoChanged = true;
			}
		});
		memoTextArea.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				if(memoChanged) {
					Controller.getInstance().saveProjectMemo(memoTextArea.getText());
					memoChanged = false;
				}
			}
		});
		memoTextArea.setTabSize(4);
		undoManager = UiUtil.addUndoRedoFeature(memoTextArea);
		scrollPane.setViewportView(memoTextArea);
		
		JPanel headerPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) headerPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		add(headerPanel, BorderLayout.NORTH);
		
		JButton btnNewButton = new JButton(Captions.PROJECT_MEMO_BUTTON_WRAP);
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				memoTextArea.setLineWrap(!memoTextArea.getLineWrap());
			}
		});
		headerPanel.add(btnNewButton);

		Controller.getInstance().setProjectMemoPanel(this);
	}

	public void refreshPanel() {
		memoTextArea.setText(Controller.getInstance().getProjectMemo());
		memoChanged = false;
		undoManager.discardAllEdits();
	}

}
