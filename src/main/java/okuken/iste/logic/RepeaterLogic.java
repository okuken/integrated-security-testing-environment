package okuken.iste.logic;

import burp.IHttpRequestResponse;
import okuken.iste.dto.MessageDto;
import okuken.iste.util.BurpUtil;

public class RepeaterLogic {

	private static final RepeaterLogic instance = new RepeaterLogic();
	private RepeaterLogic() {}
	public static RepeaterLogic getInstance() {
		return instance;
	}

	public MessageDto sendRequest(byte[] request, MessageDto orgMessageDto) {

		//TODO: time
		//TODO: check request diff
		IHttpRequestResponse response = BurpUtil.getCallbacks().makeHttpRequest(
				orgMessageDto.getMessage().getHttpService(),
				request);

		//TODO: save history

		MessageDto ret = MessageLogic.getInstance().convertHttpRequestResponseToDto(response);

		return ret;
	}

}
