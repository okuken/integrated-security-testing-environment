package okuken.iste.view.auth;

import javax.swing.AbstractButton;
import javax.swing.JPanel;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageDto;
import okuken.iste.view.AbstractDockoutableTabPanel;

import java.awt.FlowLayout;
import java.util.List;
import java.awt.BorderLayout;
import javax.swing.JButton;

public class AuthPanel extends AbstractDockoutableTabPanel {

	private static final long serialVersionUID = 1L;

	private AuthAccountTablePanel authAccountTablePanel;
	private AuthConfigPanel authConfigPanel;
	private JPanel bodyPanel;
	private JPanel headerPanel;
	private JButton dockoutButton;

	public AuthPanel() {
		setLayout(new BorderLayout(0, 0));
		
		headerPanel = new JPanel();
		add(headerPanel, BorderLayout.EAST);
		headerPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		dockoutButton = new JButton();
		headerPanel.add(dockoutButton);
		setupDockout();
		
		bodyPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) bodyPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(bodyPanel, BorderLayout.CENTER);
		
		authAccountTablePanel = new AuthAccountTablePanel();
		bodyPanel.add(authAccountTablePanel);
		
		authConfigPanel = new AuthConfigPanel();
		bodyPanel.add(authConfigPanel);

	}

	public void refreshPanel(List<MessageDto> messageDtos) {
		authAccountTablePanel.refreshPanel();
		authConfigPanel.refreshPanel(messageDtos);
	}

	public void refreshConfigPanel(List<MessageDto> messageDtos) {
		authConfigPanel.refreshPanel(messageDtos);
	}

	@Override
	protected AbstractButton getDockoutButton() {
		return dockoutButton;
	}
	@Override
	protected String getTabName() {
		return Captions.TAB_AUTH;
	}
	@Override
	protected int getTabIndex() {
		return 2; //TODO: consider other dockout
	}

}
