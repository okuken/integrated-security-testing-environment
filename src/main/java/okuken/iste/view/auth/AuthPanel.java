package okuken.iste.view.auth;

import javax.swing.AbstractButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import okuken.iste.consts.Captions;
import okuken.iste.dto.MessageDto;
import okuken.iste.view.AbstractDockoutableTabPanel;

import java.awt.FlowLayout;
import java.util.List;
import java.awt.BorderLayout;
import javax.swing.JButton;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;

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
		
		JScrollPane bodyScrollPane = new JScrollPane();
		bodyScrollPane.setBorder(null);
		add(bodyScrollPane, BorderLayout.CENTER);
		
		bodyPanel = new JPanel();
		bodyScrollPane.setViewportView(bodyPanel);
		
		authAccountTablePanel = new AuthAccountTablePanel();
		
		authConfigPanel = new AuthConfigPanel();
		
		GroupLayout gl_bodyPanel = new GroupLayout(bodyPanel);
		gl_bodyPanel.setHorizontalGroup(
			gl_bodyPanel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_bodyPanel.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_bodyPanel.createParallelGroup(Alignment.LEADING)
						.addComponent(authAccountTablePanel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(authConfigPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
					.addContainerGap())
		);
		gl_bodyPanel.setVerticalGroup(
			gl_bodyPanel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_bodyPanel.createSequentialGroup()
					.addContainerGap()
					.addComponent(authAccountTablePanel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(authConfigPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
					.addContainerGap())
		);
		bodyPanel.setLayout(gl_bodyPanel);
		
	}

	public void refreshPanel(List<MessageDto> messageDtos) {
		authAccountTablePanel.refreshPanel();
		authConfigPanel.refreshPanel();
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
