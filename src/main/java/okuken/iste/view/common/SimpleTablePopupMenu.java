package okuken.iste.view.common;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import okuken.iste.consts.Captions;
import okuken.iste.util.UiUtil;
import okuken.iste.view.AbstractAction;

import java.util.Arrays;
import java.util.Collections;
import java.util.stream.Collectors;
import java.awt.event.ActionEvent;

public class SimpleTablePopupMenu<T> extends JPopupMenu {

	private static final long serialVersionUID = 1L;

	private SimpleTablePanel<T> simpleTablePanel;

	public SimpleTablePopupMenu(SimpleTablePanel<T> simpleTablePanel) {
		this.simpleTablePanel = simpleTablePanel;
		init();
	}

	@SuppressWarnings("serial")
	private void init() {
		JMenuItem copyTableMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_COPY_TABLE);
		copyTableMenuItem.addActionListener(new AbstractAction() {
			public void actionPerformedSafe(ActionEvent e) {
				UiUtil.copyToClipboard(simpleTablePanel.getSelectedRowsAsTable().stream()
						.map(row -> row.stream().collect(Collectors.joining("\t")))
						.collect(Collectors.joining(System.lineSeparator())));
			}
		});
		add(copyTableMenuItem);

		if(simpleTablePanel.isStringTable()) {
			JMenuItem pasteTableMenuItem = new JMenuItem(Captions.TABLE_CONTEXT_MENU_PASTE_TABLE);
			pasteTableMenuItem.addActionListener(new AbstractAction() {
				public void actionPerformedSafe(ActionEvent e) {
					var clipboard = UiUtil.getFromClipboard();
					if(clipboard.isEmpty()) {
						return;
					}

					var dtos = Arrays.stream(clipboard.get().replaceAll("\r\n", "\n").split("\n"))
									.map(rowStr -> Arrays.asList(rowStr.split("\t")))
									.map(simpleTablePanel::convertStringRowToDto)
									.collect(Collectors.toList());

					Collections.reverse(dtos);
					var addTargetIndex = simpleTablePanel.getAddTargetIndex(true);

					dtos.forEach(dto -> simpleTablePanel.addRow(dto, addTargetIndex));

					simpleTablePanel.setSelection(addTargetIndex, addTargetIndex + dtos.size() - 1);
				}
			});
			add(pasteTableMenuItem);
		}

	}

}
