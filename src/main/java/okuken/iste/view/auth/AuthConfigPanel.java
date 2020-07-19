package okuken.iste.view.auth;

import javax.swing.JPanel;
import javax.swing.JLabel;
import java.awt.FlowLayout;
import javax.swing.JComboBox;
import java.awt.GridLayout;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;

import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import com.google.common.collect.Lists;

import burp.ICookie;
import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageCookieDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageParamDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.dto.PayloadDto;
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
		
		JLabel idParamLabel = new JLabel(Captions.AUTH_CONFIG_LOGIN_ID);
		loginRequestConfigPanel.add(idParamLabel);
		
		idParamComboBox = new JComboBox<MessageParamDto>();
		loginRequestConfigPanel.add(idParamComboBox);
		
		JLabel passwordParamLabel = new JLabel(Captions.AUTH_CONFIG_LOGIN_PW);
		loginRequestConfigPanel.add(passwordParamLabel);
		
		passwordParamComboBox = new JComboBox<MessageParamDto>();
		loginRequestConfigPanel.add(passwordParamComboBox);
		
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
				Executors.newSingleThreadExecutor().submit(() -> {
					AuthAccountDto authAccountDto = Controller.getInstance().getAuthAccounts().get(0); //first row
					sendLoginRequestAndSetSessionId(authAccountDto);
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
		testResultTextField.setColumns(10);
		
	}

	public void sendLoginRequestAndSetSessionId(AuthAccountDto authAccountDto) {
		MessageRepeatDto messageRepeatDto = sendLoginRequest();
		MessageCookieDto sessionIdCookieDto = sessionIdParamComboBox.getItemAt(sessionIdParamComboBox.getSelectedIndex());
		Optional<ICookie> cookieOptional = BurpUtil.getHelpers().analyzeResponse(messageRepeatDto.getMessage().getResponse()).getCookies().stream()
				.filter(cookie -> cookie.getName().equals(sessionIdCookieDto.getName()))
				.findFirst();
		if(cookieOptional.isPresent()) {
			authAccountDto.setSessionId(cookieOptional.get().getValue());
		}
	}
	private MessageRepeatDto sendLoginRequest() {
		//TODO: validation
		return Controller.getInstance().sendAutoRequest(
				createLoginPayload(Controller.getInstance().getAuthAccounts().get(0)),
				loginUrlComboBox.getItemAt(loginUrlComboBox.getSelectedIndex()));
	}
	private List<PayloadDto> createLoginPayload(AuthAccountDto authAccountDto) {
		List<PayloadDto> ret = Lists.newArrayList();

		MessageParamDto idParamDto = idParamComboBox.getItemAt(idParamComboBox.getSelectedIndex());
		ret.add(new PayloadDto(idParamDto.getName(), idParamDto.getType(), authAccountDto.getUserId()));

		MessageParamDto passwordParamDto = passwordParamComboBox.getItemAt(passwordParamComboBox.getSelectedIndex());
		ret.add(new PayloadDto(passwordParamDto.getName(), passwordParamDto.getType(), authAccountDto.getPassword()));

		return ret;
	}

	public void refreshPanel(List<MessageDto> messageDtos) {
		loginUrlComboBox.removeAllItems();
		loginUrlComboBox.setMaximumRowCount(1000);
		messageDtos.forEach(messageDto -> {
			loginUrlComboBox.addItem(messageDto);
		});

		refreshParamComboBox();
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
