package okuken.iste.plugin.api;

import java.util.List;

import javax.swing.JMenuItem;

public interface IIsteContextMenuFactory {
	List<JMenuItem> createMenuItems(IIsteContextMenuInvocation invocation);
}
