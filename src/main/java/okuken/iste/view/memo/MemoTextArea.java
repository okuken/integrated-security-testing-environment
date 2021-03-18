package okuken.iste.view.memo;

import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.Optional;
import java.util.function.Consumer;

import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import okuken.iste.util.UiUtil;

public class MemoTextArea extends JTextArea {

	private static final long serialVersionUID = 1L;

	private boolean memoChanged;

	public MemoTextArea(String memo, Consumer<String> saver) {
		super();

		setText(Optional.ofNullable(memo).orElse(""));

		getDocument().addDocumentListener(new DocumentListener() {
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

		addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				if(memoChanged) {
					if(saver != null) {
						saver.accept(getText());
					}
					memoChanged = false;
				}
			}
		});
		setTabSize(4);
		UiUtil.addUndoRedoFeature(this);
	}

}
