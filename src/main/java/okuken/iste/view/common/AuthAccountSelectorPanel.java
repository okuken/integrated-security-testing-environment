package okuken.iste.view.common;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.UiUtil;

public class AuthAccountSelectorPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private JComboBox<AuthAccountDto> authAccountComboBox;
	private JButton authSessionRefreshButton;
	private JLabel authSessionValueLabel;

	private Consumer<List<AuthAccountDto>> authAccountChangeListener;
	private Consumer<AuthAccountDto> authAccountSessionChangeListener;

	private boolean forAuthChainSetting;

	public AuthAccountSelectorPanel(boolean forAuthChainSetting) {
		this.forAuthChainSetting = forAuthChainSetting;
		
		authAccountComboBox = new JComboBox<AuthAccountDto>();
		authAccountComboBox.setToolTipText(Captions.REPEATER_COMBOBOX_ACCOUNT_TT);
		authAccountComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				authSessionRefreshButton.setEnabled(authAccountComboBox.getSelectedIndex() > 0);
				refreshAuthSessionValueLabel();
			}
		});
		add(authAccountComboBox);
		
		authAccountChangeListener = accounts -> {
			SwingUtilities.invokeLater(() -> {
				refreshComboBox();
			});
		};
		ConfigLogic.getInstance().addAuthAccountChangeListener(authAccountChangeListener);
		
		authSessionRefreshButton = new JButton(Captions.REPEATER_BUTTON_AUTH_SESSION_REFRESH);
		authSessionRefreshButton.setToolTipText(Captions.REPEATER_BUTTON_AUTH_SESSION_REFRESH_TT);
		authSessionRefreshButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = authAccountComboBox.getSelectedIndex();
				if(selectedIndex < 1) { //dummy
					return;
				}
				
				authSessionRefreshButton.setEnabled(false);
				Controller.getInstance().fetchNewAuthSession(authAccountComboBox.getItemAt(selectedIndex), x -> {
					authSessionRefreshButton.setEnabled(true);
				});
			}
		});
		if(!forAuthChainSetting) {
			add(authSessionRefreshButton);
		}
		
		authSessionValueLabel = new JLabel();
		if(!forAuthChainSetting) {
			add(authSessionValueLabel);
		}
		
		authAccountSessionChangeListener = account -> {
			SwingUtilities.invokeLater(() -> {
				refreshAuthSessionValueLabel();
			});
		};
		ConfigLogic.getInstance().addAuthAccountSessionChangeListener(authAccountSessionChangeListener);
		
	}

	public void refreshComboBox() {
		var bkSelectedId = getSelectedAuthAccountDtoId();

		authAccountComboBox.removeAllItems();
		authAccountComboBox.addItem(new AuthAccountDto()); //dummy
		authAccountComboBox.setEnabled(false);
		authSessionRefreshButton.setEnabled(false);
		authSessionValueLabel.setText(null);

		if(!ConfigLogic.getInstance().isAuthConfigReady() && !forAuthChainSetting) {
			return;
		}

		Controller.getInstance().getAuthAccounts().forEach(authAccount -> {
			authAccountComboBox.addItem(authAccount);
		});
		authAccountComboBox.setEnabled(authAccountComboBox.getItemCount() > 1);

		if(bkSelectedId != null) {
			var indexOptional = IntStream.range(0, authAccountComboBox.getItemCount())
									.filter(i -> bkSelectedId.equals(authAccountComboBox.getItemAt(i).getId())).findFirst();
			if(indexOptional.isPresent()) {
				authAccountComboBox.setSelectedIndex(indexOptional.getAsInt());
			}
		}
	}

	private void refreshAuthSessionValueLabel() {
		var authAccountDto = getSelectedAuthAccountDto();
		if(authAccountDto == null) {
			authSessionValueLabel.setText(null);
			authSessionValueLabel.setComponentPopupMenu(null);
			return;
		}

		authSessionValueLabel.setText(authAccountDto.getSessionIdForDisplay());
		if(!authAccountDto.isSessionIdsEmpty()) {
			authSessionValueLabel.setComponentPopupMenu(
				UiUtil.createCopyPopupMenu(authAccountDto.getSessionIds().subList(0, ConfigLogic.getInstance().getAuthConfig().getAuthApplyConfigDtos().size())));
		}
	}

	public AuthAccountDto getSelectedAuthAccountDto() {
		var selectedIndex = authAccountComboBox.getSelectedIndex();
		if(selectedIndex < 1) { //dummy
			return null;
		}
		return authAccountComboBox.getItemAt(selectedIndex);
	}
	private Integer getSelectedAuthAccountDtoId() {
		var dto = getSelectedAuthAccountDto();
		if(dto == null) {
			return null;
		}
		return dto.getId();
	}

	public void unloaded() {
		ConfigLogic.getInstance().removeAuthAccountChangeListener(authAccountChangeListener);
		ConfigLogic.getInstance().removeAuthAccountSessionChangeListener(authAccountSessionChangeListener);
	}

}
