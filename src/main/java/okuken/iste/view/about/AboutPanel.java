package okuken.iste.view.about;

import javax.swing.JPanel;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;

import org.apache.commons.lang3.StringUtils;

import okuken.iste.consts.Captions;
import okuken.iste.consts.Colors;
import okuken.iste.consts.Positions;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.IsteUtil;
import okuken.iste.util.UiUtil;

import javax.swing.JButton;
import javax.swing.JEditorPane;

import java.awt.event.ActionListener;
import java.util.concurrent.Executors;
import java.awt.event.ActionEvent;
import java.awt.FlowLayout;
import javax.swing.JCheckBox;

public class AboutPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JButton checkUpdateButton;
	private JLabel checkUpdateResultMessageLabel;
	private JEditorPane checkUpdateResultMessageUrlLabel;
	private String checkUpdateResultMessage;
	private boolean upToDate;

	private JCheckBox useAutoCheckUpdateCheckBox;

	public AboutPanel() {
		FlowLayout flowLayout = (FlowLayout) getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		
		JPanel panel = new JPanel();
		add(panel);
		
		JLabel nameLabel = new JLabel(Captions.EXTENSION_NAME_FULL);
		
		JEditorPane urlLabel = UiUtil.createLinkLabel(IsteUtil.getUrl());
		
		JLabel versionLabel = new JLabel(IsteUtil.getVersion());
		
		checkUpdateButton = new JButton(Captions.ABOUT_BUTTON_CHECK_UPDATE);
		checkUpdateButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				checkUpdate();
			}
		});
		
		useAutoCheckUpdateCheckBox = new JCheckBox(Captions.ABOUT_CHECKBOX_AUTO_CHECK);
		useAutoCheckUpdateCheckBox.setToolTipText(Captions.ABOUT_CHECKBOX_AUTO_CHECK_TT);
		useAutoCheckUpdateCheckBox.setSelected(ConfigLogic.getInstance().getUserOptions().isUseAutoCheckUpdate());
		useAutoCheckUpdateCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ConfigLogic.getInstance().saveUseAutoCheckUpdate(useAutoCheckUpdateCheckBox.isSelected());
			}
		});
		
		checkUpdateResultMessageLabel = new JLabel();
		checkUpdateResultMessageLabel.setForeground(Colors.CHARACTER_HIGHLIGHT);
		
		checkUpdateResultMessageUrlLabel = UiUtil.createLinkLabel(IsteUtil.getReleasesUrl());
		checkUpdateResultMessageUrlLabel.setVisible(false);
		
		GroupLayout gl_panel = new GroupLayout(panel);
		gl_panel.setHorizontalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addContainerGap(Positions.CONTAINER_GAP, Positions.CONTAINER_GAP)
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addComponent(nameLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(urlLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(versionLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addGroup(gl_panel.createSequentialGroup()
							.addComponent(checkUpdateButton, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(useAutoCheckUpdateCheckBox, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
						.addComponent(checkUpdateResultMessageLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(checkUpdateResultMessageUrlLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE))
					.addContainerGap())
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addContainerGap(Positions.CONTAINER_GAP, Positions.CONTAINER_GAP)
					.addComponent(nameLabel)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(urlLabel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(versionLabel)
					.addGap(20)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(checkUpdateButton)
						.addComponent(useAutoCheckUpdateCheckBox))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(checkUpdateResultMessageLabel)
					.addComponent(checkUpdateResultMessageUrlLabel)
					.addContainerGap())
		);
		panel.setLayout(gl_panel);
		
		init();
	}

	private void init() {
		if(!useAutoCheckUpdateCheckBox.isSelected()) {
			return;
		}

		checkUpdate();
	}

	private void checkUpdate() {
		checkUpdateResultMessageLabel.setText(null);
		checkUpdateResultMessageUrlLabel.setVisible(false);
		checkUpdateButton.setEnabled(false);

		Executors.newSingleThreadExecutor().execute(() -> {
			try {
				var currentVersion = IsteUtil.getVersion();
				var latestVersion = IsteUtil.fetchIsteLatestVersion();
				upToDate = StringUtils.equals(currentVersion, latestVersion);

				if(upToDate) {
					checkUpdateResultMessage = Captions.MESSAGE_VERSION_LATEST;
				} else {
					checkUpdateResultMessage = String.format(Captions.MESSAGE_VERSION_NOT_LATEST, latestVersion);
				}
			} catch(Exception e) {
				BurpUtil.printStderr(e);
				checkUpdateResultMessage = e.getMessage();
			}

			UiUtil.invokeLater(() -> {
				checkUpdateButton.setEnabled(true);
				checkUpdateResultMessageLabel.setText(checkUpdateResultMessage);
				checkUpdateResultMessageUrlLabel.setVisible(!upToDate);
				if(!upToDate && useAutoCheckUpdateCheckBox.isSelected()) {
					UiUtil.highlightTab(this);
				}
			});
		});
	}
}
