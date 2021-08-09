package okuken.iste.util;

import java.awt.Component;
import java.awt.Container;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;

public class UiUtil {

	public static final Window getParentFrame(Component component) {
		if(component == null) {
			return BurpUtil.getBurpSuiteJFrame();
		}
		return SwingUtilities.getWindowAncestor(component);
	}

	public static final void repaint(JComponent component) {
		component.revalidate();
		component.repaint();
	}

	public static final JLabel createTemporaryMessageArea() {
		var ret = new JLabel(Captions.MESSAGE_EMPTY);
		ret.setForeground(Colors.CHARACTER_HIGHLIGHT);
		return ret;
	}
	public static final void showTemporaryMessage(JLabel messageArea, String message) {
		messageArea.setText(message);
		new Timer().schedule(new TimerTask() {
			@Override
			public void run() {
				SwingUtilities.invokeLater(() -> {
					messageArea.setText(Captions.MESSAGE_EMPTY);
				});
			}
		}, 1000);
	}

	/**
	 * CAUTION: support ASCII only
	 */
	public static final PrintStream createTextAreaPrintStream(JTextArea messageTextArea) {
		return new PrintStream(new OutputStream() {
			@Override
			public void write(int b) throws IOException {
				messageTextArea.append(String.valueOf((char)b));
				messageTextArea.setCaretPosition(messageTextArea.getDocument().getLength());
			}
		}, false, StandardCharsets.US_ASCII);
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
				var val = table.getModel().getValueAt(table.convertRowIndexToModel(table.getSelectedRow()), columnIndexTranslator.apply(table.getSelectedColumn()));
				copyToClipboard(val != null ? val.toString() : "");
			}
		});
	}

	public static final JPopupMenu createCopyPopupMenu(Supplier<String> supplier) {
		var menu = new JPopupMenu();
		var menuItem = new JMenuItem(Captions.COPY);
		menuItem.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				copyToClipboard(supplier.get());
			}
		});
		menu.add(menuItem);
		return menu;
	}

	public static final JPopupMenu createCopyPopupMenu(List<String> strs) {
		var menu = new JPopupMenu();
		IntStream.range(0, strs.size()).forEach(i -> {
			var str = strs.get(i);
			var menuItem = new JMenuItem(String.format("%d: %s", i + 1, str != null ? str : ""));
			menuItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					copyToClipboard(str);
				}
			});
			menu.add(menuItem);
		});
		return menu;
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

	public static boolean judgeIsForceRefresh(ActionEvent e) {
		return (e.getModifiers() & ActionEvent.SHIFT_MASK) != 0;
	}

	public static void initScrollBarPosition(JScrollPane scrollPane) {
		var verticalScrollBar = scrollPane.getVerticalScrollBar();
		verticalScrollBar.setValue(verticalScrollBar.getMinimum());
		var horizontalScrollBar = scrollPane.getHorizontalScrollBar();
		horizontalScrollBar.setValue(horizontalScrollBar.getMinimum());
	}


	private static final List<JFrame> popupFrames = Lists.newArrayList(); 
	public static void disposePopupFrames() {
		popupFrames.forEach(popupFrame -> {
			popupFrame.dispose();
		});
	}
	public static JFrame popup(String title, Container contentPane, Component triggerComponent) {
		return popup(title, contentPane, triggerComponent, null);
	}
	public static JFrame popup(String title, Container contentPane, Component triggerComponent, Consumer<WindowEvent> closeProcedure) {
		var ret = createAndShowFrame(title, contentPane, triggerComponent, closeProcedure);
		popupFrames.add(ret);
		return ret;
	}
	public static void closePopup(JFrame popupFrame) {
		popupFrame.dispose();
		popupFrames.remove(popupFrame);
	}

	private static final List<JFrame> dockoutFrames = Lists.newArrayList(); 
	public static void disposeDockoutFrames() {
		dockoutFrames.forEach(dockoutFrame -> {
			dockoutFrame.dispose();
		});
	}
	public static JFrame dockout(String title, Container contentPane, Consumer<WindowEvent> closeProcedure) {
		var ret = createAndShowFrame(title, contentPane, null, closeProcedure);
		dockoutFrames.add(ret);
		return ret;
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

	private static JFrame createAndShowFrame(String title, Container contentPane, Component triggerComponent, Consumer<WindowEvent> closeProcedure) {
		var parentFrame = getParentFrame(triggerComponent);

		JFrame popupFrame = new JFrame();
		popupFrame.setTitle(title);
		popupFrame.setBounds(parentFrame.getBounds());
		popupFrame.setContentPane(contentPane);
		popupFrame.setLocationRelativeTo(parentFrame);

		popupFrame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		popupFrame.addWindowListener(new WindowListener() {
			@Override public void windowOpened(WindowEvent e) {}
			@Override public void windowIconified(WindowEvent e) {}
			@Override public void windowDeiconified(WindowEvent e) {}
			@Override public void windowDeactivated(WindowEvent e) {}
			@Override public void windowClosing(WindowEvent e) {
				if(closeProcedure == null) {
					closePopup(popupFrame);
					return;
				}
				closeProcedure.accept(e);
			}
			@Override public void windowClosed(WindowEvent e) {}
			@Override public void windowActivated(WindowEvent e) {}
		});

		BurpUtil.getCallbacks().customizeUiComponent(popupFrame);
		popupFrame.setVisible(true);

		return popupFrame;
	}

	public static void showMessage(String message, Component triggerComponent) {
		JOptionPane.showMessageDialog(getParentFrame(triggerComponent), message);
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

	private static final DateFormat timestampForFilenameFormat = new SimpleDateFormat("yyyyMMddHHmmss");
	public static final String nowForFilename() {
		return timestampForFilenameFormat.format(Calendar.getInstance().getTime());
	}

	public static final String omitString(String str, int length) {
		if(judgeIsNotNeedOmit(str, length)) {
			return str;
		}
		int remainLength = length / 2;
		return new StringBuilder()
				.append(str.substring(0, remainLength))
				.append(Captions.OMIT_STRING)
				.append(str.substring(str.length() - remainLength, str.length()))
				.toString();
	}
	public static final String omitStringTail(String str, int length) {
		if(judgeIsNotNeedOmit(str, length)) {
			return str;
		}
		return new StringBuilder()
				.append(str.substring(0, length))
				.append(Captions.OMIT_STRING)
				.toString();
	}
	private static final boolean judgeIsNotNeedOmit(String str, int length) {
		return str == null || str.length() <= length;
	}

}
