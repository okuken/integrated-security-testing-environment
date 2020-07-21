package okuken.iste.util;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.function.Function;

import javax.swing.AbstractAction;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;

public class UiUtil {

	public static final void copyToClipboard(String content) {
		StringSelection stringSelection = new StringSelection(content);
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, stringSelection);
	}

	public static final void setupCtrlCAsCopyCell(JTable table) { 
		setupCtrlCAsCopyCell(table, c -> c);
	}

	@SuppressWarnings("serial")
	public static final void setupCtrlCAsCopyCell(JTable table, Function<Integer, Integer> columnIndexTranslator) {
		String actionMapKeyCopyCell = "Copy Cell";
		KeyStroke keyStrokeCtrlC = KeyStroke.getKeyStroke(KeyEvent.VK_C, ActionEvent.CTRL_MASK, false);
		table.getInputMap().put(keyStrokeCtrlC, actionMapKeyCopyCell);
		table.getActionMap().put(actionMapKeyCopyCell, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				copyToClipboard(table.getModel().getValueAt(table.convertRowIndexToModel(table.getSelectedRow()), columnIndexTranslator.apply(table.getSelectedColumn())).toString());
			}
		});
	}

	public static final UndoManager addUndoRedoFeature(JTextComponent textComponent) {
		UndoManager undoManager = new UndoManager();
		textComponent.getDocument().addUndoableEditListener(new UndoableEditListener() {
			@Override
			public void undoableEditHappened(UndoableEditEvent e) {
				undoManager.addEdit(e.getEdit());
			}
		});

		textComponent.addKeyListener(new KeyListener() {
			@Override
			public void keyPressed(KeyEvent e) {
				if(!e.isControlDown()) {
					return;
				}

				switch (e.getKeyCode()) {
					case KeyEvent.VK_Z:
						if(undoManager.canUndo()) {
							undoManager.undo();
						}
						e.consume();
						return;
					case KeyEvent.VK_Y:
						if(undoManager.canRedo()) {
							undoManager.redo();
						}
						e.consume();
						return;
				}
			}

			@Override
			public void keyTyped(KeyEvent e) {}
			@Override
			public void keyReleased(KeyEvent e) {}
		});

		return undoManager;
	}

	private static final DateFormat timestampFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	public static final String now() {
		return timestampFormat.format(Calendar.getInstance().getTime());
	}

}
