package okuken.iste.view.auth;

import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import java.awt.FlowLayout;
import javax.swing.JComboBox;
import java.awt.GridLayout;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.google.common.collect.Lists;

import burp.IParameter;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainNodeInDto;
import okuken.iste.dto.MessageChainNodeOutDto;
import okuken.iste.dto.MessageCookieDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageParamDto;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.util.BurpUtil;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class AuthConfigPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField testResultTextField;

	private JComboBox<MessageDto> loginUrlComboBox;
	private JComboBox<MessageParamDto> idParamComboBox;
	private JComboBox<MessageParamDto> passwordParamComboBox;

	private JComboBox<String> sessionIdParamTypeComboBox;
	private JComboBox<MessageCookieDto> sessionIdParamComboBox;

	private AuthConfigDto authConfigDto;

	public AuthConfigPanel() {
		setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel loginRequestConfigPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) loginRequestConfigPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(loginRequestConfigPanel);
		
		JLabel LoginUrlLabel = new JLabel(Captions.AUTH_CONFIG_LOGIN_URL);
		loginRequestConfigPanel.add(LoginUrlLabel);
		
		loginUrlComboBox = new JComboBox<MessageDto>();
		loginUrlComboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				refreshParamComboBox();
			}
		});
		loginRequestConfigPanel.add(loginUrlComboBox);
		
		JPanel loginRequestParamConfigPanel = new JPanel();
		FlowLayout flowLayout_3 = (FlowLayout) loginRequestParamConfigPanel.getLayout();
		flowLayout_3.setAlignment(FlowLayout.LEFT);
		add(loginRequestParamConfigPanel);
		
		JLabel idParamLabel = new JLabel(Captions.AUTH_CONFIG_LOGIN_ID);
		loginRequestParamConfigPanel.add(idParamLabel);
		
		idParamComboBox = new JComboBox<MessageParamDto>();
		loginRequestParamConfigPanel.add(idParamComboBox);
		
		JLabel passwordParamLabel = new JLabel(Captions.AUTH_CONFIG_LOGIN_PW);
		loginRequestParamConfigPanel.add(passwordParamLabel);
		
		passwordParamComboBox = new JComboBox<MessageParamDto>();
		loginRequestParamConfigPanel.add(passwordParamComboBox);
		
		JPanel loginResponseConfigPanel = new JPanel();
		FlowLayout flowLayout_1 = (FlowLayout) loginResponseConfigPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.LEFT);
		add(loginResponseConfigPanel);
		
		JLabel sessionIdParamLabel = new JLabel(Captions.AUTH_CONFIG_SESSIONID);
		loginResponseConfigPanel.add(sessionIdParamLabel);
		
		sessionIdParamTypeComboBox = new JComboBox<String>();
		sessionIdParamTypeComboBox.addItem("Cookie"); //TODO: support response body (JSON, ...)
		loginResponseConfigPanel.add(sessionIdParamTypeComboBox);
		
		sessionIdParamComboBox = new JComboBox<MessageCookieDto>();
		loginResponseConfigPanel.add(sessionIdParamComboBox);
		
		JPanel loginTestPanel = new JPanel();
		FlowLayout flowLayout_2 = (FlowLayout) loginTestPanel.getLayout();
		flowLayout_2.setAlignment(FlowLayout.LEFT);
		add(loginTestPanel);
		
		JButton testLoginButton = new JButton(Captions.AUTH_CONFIG_BUTTON_LOGIN_TEST);
		testLoginButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(!validateAndShowPopup()) {
					return;
				}

				List<AuthAccountDto> authAccountDtos = Controller.getInstance().getAuthAccounts();
				if(authAccountDtos.isEmpty()) {
					JOptionPane.showMessageDialog(BurpUtil.getBurpSuiteJFrame(), "Please register one or more account information.");
					return;
				}
				AuthAccountDto authAccountDto = authAccountDtos.get(0);//TODO: selected row

				Executors.newSingleThreadExecutor().submit(() -> {
					Controller.getInstance().fetchNewAuthSession(authAccountDto, createChainDto(), true);
					SwingUtilities.invokeLater(() -> {
						if(authAccountDto.getSessionId() != null) {
							testResultTextField.setText(authAccountDto.getSessionId());
						} else {
							testResultTextField.setText("ERROR: Response doesn't have selected cookie.");
						}
					});
				});
			}
		});
		loginTestPanel.add(testLoginButton);
		
		testResultTextField = new JTextField();
		testResultTextField.setEditable(false);
		loginTestPanel.add(testResultTextField);
		testResultTextField.setColumns(20);
		
		JButton saveButton = new JButton(Captions.AUTH_CONFIG_BUTTON_SAVE);
		saveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(validateAndShowPopup()) {
					saveConfig();
				}
			}
		});
		loginTestPanel.add(saveButton);
		
	}

	private boolean validateAndShowPopup() {
		boolean ret = validateInputs();
		if(!ret) {
			JOptionPane.showMessageDialog(BurpUtil.getBurpSuiteJFrame(), "Please fill in all fields.");
		}
		return ret;
	}
	private boolean validateInputs() {
		return idParamComboBox.getSelectedIndex() > -1 &&
				passwordParamComboBox.getSelectedIndex() > -1 &&
				sessionIdParamComboBox.getSelectedIndex() > -1;
	}

	private void saveConfig() {
		authConfigDto = Controller.getInstance().saveAuthConfig(createChainDto());
	}
	private MessageChainDto createChainDto() {
		var ret = new MessageChainDto();

		var nodeDto = new MessageChainNodeDto();
		nodeDto.setMessageDto(loginUrlComboBox.getItemAt(loginUrlComboBox.getSelectedIndex()));
		ret.setNodes(Lists.newArrayList(nodeDto));

		nodeDto.setIns(Lists.newArrayList(
				convertToChainNodeInDto(idParamComboBox.getItemAt(idParamComboBox.getSelectedIndex())),
				convertToChainNodeInDto(passwordParamComboBox.getItemAt(passwordParamComboBox.getSelectedIndex()))));

		nodeDto.setOuts(Lists.newArrayList(
				convertToChainNodeOutDto(sessionIdParamComboBox.getItemAt(sessionIdParamComboBox.getSelectedIndex()))));

		return ret;
	}
	private MessageChainNodeInDto convertToChainNodeInDto(MessageParamDto paramDto) {
		var ret = new MessageChainNodeInDto();
		ret.setParamType(paramDto.getType());
		ret.setParamName(paramDto.getName());
		return ret;
	}
	private MessageChainNodeOutDto convertToChainNodeOutDto(MessageCookieDto cookieDto) {
		var ret = new MessageChainNodeOutDto();
		ret.setParamType(IParameter.PARAM_COOKIE);
		ret.setParamName(cookieDto.getName());
		ret.setVarName(cookieDto.getName());
		return ret;
	}

	public void refreshPanel(List<MessageDto> messageDtos) {
		loginUrlComboBox.removeAllItems();
		loginUrlComboBox.setMaximumRowCount(1000);
		messageDtos.forEach(messageDto -> {
			loginUrlComboBox.addItem(messageDto);
		});

		authConfigDto = ConfigLogic.getInstance().getAuthConfig();
		if(authConfigDto == null) {
			refreshParamComboBox();
			return;
		}

		var chainNodeDto = authConfigDto.getAuthMessageChainDto().getNodes().get(0); //now, support only one node
		loginUrlComboBox.setSelectedItem(messageDtos.stream().filter(messageDto -> messageDto.getId().equals(chainNodeDto.getMessageDto().getId())).findFirst().get());

		refreshParamComboBox();

		var idInDto = chainNodeDto.getIns().get(0);//...
		idParamComboBox.setSelectedIndex(
			IntStream.range(0, idParamComboBox.getItemCount()).filter(i -> {
				var idParamDto = idParamComboBox.getItemAt(i);
				return idParamDto.getType() == idInDto.getParamType() &&
						idParamDto.getName().equals(idInDto.getParamName());
				}).findFirst().getAsInt());

		var pwInDto = chainNodeDto.getIns().get(1);//...
		passwordParamComboBox.setSelectedIndex(
			IntStream.range(0, passwordParamComboBox.getItemCount()).filter(i -> {
				var pwParamDto = passwordParamComboBox.getItemAt(i);
				return pwParamDto.getType() == pwInDto.getParamType() &&
						pwParamDto.getName().equals(pwInDto.getParamName());
				}).findFirst().getAsInt());

		var sessIdOutDto = chainNodeDto.getOuts().get(0);//...
		sessionIdParamComboBox.setSelectedIndex(
			IntStream.range(0, sessionIdParamComboBox.getItemCount()).filter(i -> {
				var sessIdCookieDto = sessionIdParamComboBox.getItemAt(i);
				return sessIdCookieDto.getName().equals(sessIdOutDto.getParamName());
				}).findFirst().getAsInt());

	}

	private void refreshParamComboBox() {
		idParamComboBox.removeAllItems();
		passwordParamComboBox.removeAllItems();
		sessionIdParamComboBox.removeAllItems();

		if(loginUrlComboBox.getItemCount() < 1) {
			return;
		}

		idParamComboBox.setMaximumRowCount(1000);
		loginUrlComboBox.getItemAt(loginUrlComboBox.getSelectedIndex()).getMessageParamList().forEach(messagePramDto -> {
			idParamComboBox.addItem(messagePramDto);
		});

		passwordParamComboBox.setMaximumRowCount(1000);
		loginUrlComboBox.getItemAt(loginUrlComboBox.getSelectedIndex()).getMessageParamList().forEach(messagePramDto -> {
			passwordParamComboBox.addItem(messagePramDto);
		});

		sessionIdParamComboBox.setMaximumRowCount(1000);
		loginUrlComboBox.getItemAt(loginUrlComboBox.getSelectedIndex()).getMessageCookieList().forEach(messageCookieDto -> {
			sessionIdParamComboBox.addItem(messageCookieDto);
		});
	}

}
