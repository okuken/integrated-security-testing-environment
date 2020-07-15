package okuken.iste.view.auth;

import javax.swing.JPanel;

import java.awt.BorderLayout;

public class AuthPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private AuthAccountTablePanel authTablePanel;

	public AuthPanel() {
		setLayout(new BorderLayout(0, 0));
		
		authTablePanel = new AuthAccountTablePanel();
		add(authTablePanel, BorderLayout.CENTER);
		
		JPanel authConfigPanel = new AuthConfigPanel();
		add(authConfigPanel, BorderLayout.SOUTH);

	}

	public void refreshPanel() {
		authTablePanel.refreshPanel();
	}

}
