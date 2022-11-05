package okuken.iste.view.message.editor;

import java.awt.Component;

public interface HttpMessageEditor {
	Component getComponent();
	void setMessage(byte[] message, boolean isRequest);
	byte[] getMessage();
	boolean isMessageModified();
	byte[] getSelectedData();
	int[] getSelectionBounds();
}
