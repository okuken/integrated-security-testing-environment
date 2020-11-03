package okuken.iste.util;

import java.awt.Component;
import java.awt.Container;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.function.Function;

import javax.swing.AbstractAction;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;

public class UiUtil {

	public static final Window getParentFrame(Component component) {
		if(component == null) {
			return BurpUtil.getBurpSuiteJFrame();
		}
		return SwingUtilities.getWindowAncestor(component);
	}

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

	public static void initScrollBarPosition(JScrollPane scrollPane) {
		var verticalScrollBar = scrollPane.getVerticalScrollBar();
		verticalScrollBar.setValue(verticalScrollBar.getMinimum());
		var horizontalScrollBar = scrollPane.getHorizontalScrollBar();
		horizontalScrollBar.setValue(horizontalScrollBar.getMinimum());
	}


	private static final List<JFrame> dockoutFrames = Lists.newArrayList(); 
	public static void disposeDockoutFrames() {
		dockoutFrames.forEach(dockoutFrame -> {
			dockoutFrame.dispose();
		});
	}

	public static JFrame dockout(String title, Container contentPane) {
		JFrame burpSuiteFrame = BurpUtil.getBurpSuiteJFrame();

		JFrame dockoutFrame = new JFrame();
		dockoutFrame.setTitle(title);
		dockoutFrame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		dockoutFrame.setBounds(burpSuiteFrame.getBounds());
		dockoutFrame.setContentPane(contentPane);
		dockoutFrame.setLocationRelativeTo(burpSuiteFrame);
		dockoutFrame.setVisible(true);

		dockoutFrames.add(dockoutFrame);

		return dockoutFrame;
	}

	public static void dockin(Container contentPane, Container parentContainer, JFrame dockoutFrame) {
		parentContainer.add(contentPane);
		dockinAfterProcess(dockoutFrame);
	}
	public static void dockin(String tabName, Container contentPane, int tabIndex, JTabbedPane parentTabbedPane, JFrame dockoutFrame) {
		parentTabbedPane.insertTab(tabName, null, contentPane, null, tabIndex);
		parentTabbedPane.setSelectedIndex(tabIndex);
		dockinAfterProcess(dockoutFrame);
	}
	private static void dockinAfterProcess(JFrame dockoutFrame) {
		dockoutFrame.dispose();
		dockoutFrames.remove(dockoutFrame);
	}

	public static String createDockoutTitleByTabName(String tabName) {
		return String.format("%s - %s", tabName, Captions.EXTENSION_NAME_FULL);
	}


	public static boolean getConfirmAnswer(String message) {
		return getConfirmAnswer(message, null);
	}
	public static boolean getConfirmAnswer(String message, Component triggerComponent) {
		return JOptionPane.showConfirmDialog(getParentFrame(triggerComponent), 
				message, String.format("Confirm [%s]", Captions.EXTENSION_NAME_FULL), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION;
	}

	private static final DateFormat timestampFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	public static final String now() {
		return timestampFormat.format(Calendar.getInstance().getTime());
	}

}
