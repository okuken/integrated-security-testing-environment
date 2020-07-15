package okuken.iste.view.auth;

import javax.swing.JPanel;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class AuthPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private AuthAccountTablePanel authAccountTablePanel;

	public AuthPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel panel = new JPanel();
		add(panel);
		panel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		authAccountTablePanel = new AuthAccountTablePanel();
		panel.add(authAccountTablePanel);
		
		JPanel authConfigPanel = new AuthConfigPanel();
		add(authConfigPanel, BorderLayout.SOUTH);

	}

	public void refreshPanel() {
		authAccountTablePanel.refreshPanel();
	}

}
