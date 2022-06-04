package okuken.iste.util;

import java.awt.Component;
import java.awt.Container;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.Action;
import javax.swing.DefaultCellEditor;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
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
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.JTextComponent;
import javax.swing.undo.UndoManager;

import com.google.common.collect.Lists;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.view.AbstractAction;

public class UiUtil {

	public static final void invokeLater(Runnable doRun) {
		SwingUtilities.invokeLater(() -> {
			try {
				doRun.run();
			} catch (Exception e) {
				BurpUtil.printStderr(e);
			}
		});
	}

	public static final String getLookAndFeelName() {
		var lookAndFeel = UIManager.getLookAndFeel();
		if(lookAndFeel == null) {
			return "";
		}
		return lookAndFeel.toString();
	}

	public static final Window getParentFrame(Component component) {
		if(component == null) {
			return BurpUtil.getBurpSuiteJFrame();
		}
		return SwingUtilities.getWindowAncestor(component);
	}

	public static final Integer getNextTableModelRow(List<Integer> tableModelRowIndexs, JTable table) {
		if(tableModelRowIndexs.isEmpty()) {
			return null;
		}
		var tableModelRowIndex = tableModelRowIndexs.get(tableModelRowIndexs.size() - 1);

		var viewIndex = table.convertRowIndexToView(tableModelRowIndex);
		if(viewIndex + 1 >= table.getRowCount()) {
			return null;
		}

		return table.convertRowIndexToModel(viewIndex + 1);
	}

	public static final void repaint(JComponent component) {
		component.revalidate();
		component.repaint();
	}

	public static void withKeepCaretPosition(JTextComponent textComponent, Runnable procedure) {
		if(textComponent == null) {
			procedure.run();
			return;
		}

		var hasFocus = textComponent.hasFocus();
		var caretPosition = textComponent.getCaretPosition();

		procedure.run();

		try {
			var textLength = textComponent.getText().length();

			if(caretPosition < textLength) {
				textComponent.setCaretPosition(caretPosition);
			} else {
				textComponent.setCaretPosition(textLength);
			}

			if(hasFocus) {
				focus(textComponent);
			}
		} catch (Exception e) {
			BurpUtil.printStderr(e);
		}
	}

	public static final void focus(JComponent component) {
		component.requestFocusInWindow();
	}

	public static final void scrollFor(Component component, JScrollPane scrollPane) {
		scrollPane.getViewport().setViewPosition(component.getLocation());
	}

	public static void highlightTab(Component tabComponent) {
		JTabbedPane parentTabbedPane = (JTabbedPane)tabComponent.getParent();
		parentTabbedPane.setForegroundAt(parentTabbedPane.indexOfComponent(tabComponent), Colors.CHARACTER_HIGHLIGHT);
	}

	public static final JLabel createTemporaryMessageArea() {
		var ret = new JLabel(Captions.MESSAGE_EMPTY);
		ret.setForeground(Colors.CHARACTER_HIGHLIGHT);
		invokeLater(() -> {
			setupHtmlEnable(ret);
		});
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

	public static void setupHtmlEnable(JLabel label) {
		label.putClientProperty("html.disable", Boolean.FALSE);
	}

	public static final JLabel createSpacer() {
		return createSpacer(1);
	}
	public static final JLabel createSpacerM() {
		return createSpacer(2);
	}
	private static final JLabel createSpacer(int size) {
		var spaceStr = IntStream.range(0, size).mapToObj(i -> "  ").collect(Collectors.joining());
		return new JLabel(spaceStr);
	}

	public static final JEditorPane createLinkLabel(String url) {
		return createLinkLabel(url, url);
	}
	public static final JEditorPane createLinkLabel(String caption, String url) {
		JEditorPane ret = new JEditorPane("text/html", String.format("<a href=\"%s\">%s</a>", url, caption));
		ret.setEditable(false);
		ret.setBorder(new EmptyBorder(0, 0, 0, 0));
		ret.addHyperlinkListener(new HyperlinkListener() {
			public void hyperlinkUpdate(HyperlinkEvent e) {
				if(!HyperlinkEvent.EventType.ACTIVATED.equals(e.getEventType())) {
					return;
				}
				try {
					Desktop.getDesktop().browse(URI.create(url));
				} catch (Exception ex) {
					BurpUtil.printStderr(ex);
				}
			}
		});
		return ret;
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
			public void actionPerformedSafe(ActionEvent e) {
				if(table.getSelectedRow() < 0) {
					return;
				}

				var val = table.getModel().getValueAt(table.convertRowIndexToModel(table.getSelectedRow()), columnIndexTranslator.apply(table.getSelectedColumn()));
				copyToClipboard(val != null ? val.toString() : "");
			}
		});
	}

	public static void setupStopEditingOnFocusLost(JTable table) {
		table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
		((DefaultCellEditor)table.getDefaultEditor(Object.class)).getComponent().addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				stopEditing(table);
			}
		});
	}
	public static void stopEditing(JTable table) {
		if(table.isEditing()) {
			table.getCellEditor().stopCellEditing();
		}
	}

	public static void setupShortcutKey(JComponent component, KeyStroke keyStroke, Action action) {
		component.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(keyStroke, keyStroke);
		component.getActionMap().put(keyStroke, action);
	}

	public static void setupTablePopupMenuItem(JMenuItem menuItem, JTable table, KeyStroke keyStroke, Action action) {
		menuItem.addActionListener(action);
		menuItem.setAccelerator(keyStroke);
		table.getInputMap().put(keyStroke, menuItem);
		table.getActionMap().put(menuItem, action);
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
		return judgeIsShiftDown(e);
	}
	public static boolean judgeIsShiftDown(ActionEvent e) {
		return (e.getModifiers() & ActionEvent.SHIFT_MASK) != 0;
	}

	public static void initScrollBarPosition(JScrollPane scrollPane) {
		var verticalScrollBar = scrollPane.getVerticalScrollBar();
		verticalScrollBar.setValue(verticalScrollBar.getMinimum());
		var horizontalScrollBar = scrollPane.getHorizontalScrollBar();
		horizontalScrollBar.setValue(horizontalScrollBar.getMinimum());
	}

	public static void setupScrollPaneMouseWheelDispatch(JScrollPane scrollPane, JScrollPane parentScrollPane) {
		scrollPane.setWheelScrollingEnabled(false);
		scrollPane.addMouseWheelListener(new MouseWheelListener() {
			public void mouseWheelMoved(MouseWheelEvent e) {
				parentScrollPane.dispatchEvent(e);
			}
		});
	}

	public static void setOpaqueChildComponents(Container container, boolean opaque) {
		Arrays.stream(container.getComponents()).forEach(c -> setOpaqueChildComponentsImpl(c, opaque));
	}
	private static void setOpaqueChildComponentsImpl(Component component, boolean opaque) {
		if(component instanceof JComponent) {
			((JComponent)component).setOpaque(opaque);
		}
		if(component instanceof Container) {
			Arrays.stream(((Container)component).getComponents()).forEach(child -> {
				setOpaqueChildComponentsImpl(child, opaque); //recursive
			});
		}
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
		JOptionPane.showMessageDialog(getParentFrame(triggerComponent), message, Captions.EXTENSION_NAME_FULL, JOptionPane.ERROR_MESSAGE);
	}
	public static void showInfoMessage(String message, Component triggerComponent) {
		JOptionPane.showMessageDialog(getParentFrame(triggerComponent), message, Captions.EXTENSION_NAME_FULL, JOptionPane.INFORMATION_MESSAGE);
	}

	public static boolean getConfirmAnswer(String message) {
		return getConfirmAnswer(message, null);
	}
	public static boolean getConfirmAnswer(String message, Component triggerComponent) {
		return JOptionPane.showConfirmDialog(getParentFrame(triggerComponent), 
				message, String.format("Confirm [%s]", Captions.EXTENSION_NAME_FULL), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION;
	}

	public static boolean getConfirmAnswerDefaultCancel(String message, Component triggerComponent) {
		Object[] options = {Captions.OK, Captions.CANCEL};
		return JOptionPane.showOptionDialog(getParentFrame(triggerComponent), 
				message, String.format("Confirm [%s]", Captions.EXTENSION_NAME_FULL), JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]) == JOptionPane.OK_OPTION;
	}

	public static int showOptionDialog(Component parentComponent, JComponent component, String title, int optionType, int messageType,
			Icon icon, Object[] options, Object initialValue) {

		// focus on component
		component.addAncestorListener(new AncestorListener() {
			@Override
			public void ancestorAdded(AncestorEvent event) {
				var component = event.getComponent();
				focus(component);
				component.removeAncestorListener(this);
			}
			@Override
			public void ancestorRemoved(AncestorEvent event) {}
			@Override
			public void ancestorMoved(AncestorEvent event) {}
		});

		return JOptionPane.showOptionDialog(parentComponent, component, title, optionType, messageType, icon, options, initialValue);
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
