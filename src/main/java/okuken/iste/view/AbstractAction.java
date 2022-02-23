package okuken.iste.view;

import java.awt.event.ActionEvent;

import okuken.iste.util.BurpUtil;

public abstract class AbstractAction extends javax.swing.AbstractAction {

	private static final long serialVersionUID = 1L;

	public abstract void actionPerformedSafe(ActionEvent e);

	@Override
	public final void actionPerformed(ActionEvent e) {
		try {
			actionPerformedSafe(e);
		} catch (Exception ex) {
			BurpUtil.printStderr(ex);
		}
	}

}
