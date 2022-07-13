package okuken.iste.view.auth;

import javax.swing.JPanel;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;

import okuken.iste.consts.Captions;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.view.chain.ChainDefPanel;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class AuthConfigPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private AuthApplyConfigPanel authApplyConfigPanel;

	public AuthConfigPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel loginRequestConfigPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) loginRequestConfigPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(loginRequestConfigPanel, BorderLayout.NORTH);
		
		JButton chainEditButton = new JButton(Captions.AUTH_CONFIG_BUTTON_EDIT_CHAIN);
		chainEditButton.setToolTipText(Captions.AUTH_CONFIG_BUTTON_EDIT_CHAIN_TT);
		loginRequestConfigPanel.add(chainEditButton);
		chainEditButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ChainDefPanel.openChainFrame(ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainId(), chainEditButton, Captions.AUTH_CONFIG_POPUP_TITLE_EDIT_CHAIN);
			}
		});
		
		authApplyConfigPanel = new AuthApplyConfigPanel();
		add(authApplyConfigPanel, BorderLayout.CENTER);
		
	}

	public void refreshPanel() {
		authApplyConfigPanel.refreshPanel();
	}

}
