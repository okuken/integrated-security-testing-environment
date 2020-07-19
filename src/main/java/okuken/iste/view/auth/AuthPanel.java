package okuken.iste.view.auth;

import javax.swing.JPanel;

import okuken.iste.dto.MessageDto;

import java.awt.FlowLayout;
import java.util.List;

public class AuthPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private AuthAccountTablePanel authAccountTablePanel;
	private AuthConfigPanel authConfigPanel;

	public AuthPanel() {
		setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JPanel panel = new JPanel();
		add(panel);
		panel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		authAccountTablePanel = new AuthAccountTablePanel();
		panel.add(authAccountTablePanel);
		
		authConfigPanel = new AuthConfigPanel();
		add(authConfigPanel);

	}

	public void refreshPanel(List<MessageDto> messageDtos) {
		authAccountTablePanel.refreshPanel();
		authConfigPanel.refreshPanel(messageDtos);
	}

	public void refreshConfigPanel(List<MessageDto> messageDtos) {
		authConfigPanel.refreshPanel(messageDtos);
	}

}
