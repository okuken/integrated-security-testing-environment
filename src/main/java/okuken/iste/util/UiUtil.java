package okuken.iste.util;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

public class UiUtil {

	public static final void copyToClipboard(String content) {
		StringSelection stringSelection = new StringSelection(content);
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, stringSelection);
	}

}
