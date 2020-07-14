package okuken.iste.logic;

import java.util.Calendar;
import java.util.Date;

import burp.IHttpRequestResponse;
import okuken.iste.dao.MessageRawMapper;
import okuken.iste.dao.MessageRepeatMapper;
import okuken.iste.dto.MessageDto;
import okuken.iste.entity.MessageRaw;
import okuken.iste.entity.MessageRepeat;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;

public class RepeaterLogic {

	private static final RepeaterLogic instance = new RepeaterLogic();
	private RepeaterLogic() {}
	public static RepeaterLogic getInstance() {
		return instance;
	}

	public MessageDto sendRequest(byte[] request, MessageDto orgMessageDto) {
		try {
			Date sendDate = Calendar.getInstance().getTime();
			long timerStart = System.currentTimeMillis();

			IHttpRequestResponse response = BurpUtil.getCallbacks().makeHttpRequest(
					orgMessageDto.getMessage().getHttpService(),
					request);

			long timerEnd = System.currentTimeMillis();
			int time = (int) (timerEnd - timerStart);

			MessageDto ret = MessageLogic.getInstance().convertHttpRequestResponseToDto(response);
			ret.setSendDate(sendDate);
			ret.setTime(time);
			ret.setDifference("");//TODO: impl

			save(ret, orgMessageDto.getId());

			return ret;

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	private void save(MessageDto messageDto, Integer orgMessageId) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
			MessageRepeatMapper messageRepeatMapper = session.getMapper(MessageRepeatMapper.class);

			//TODO: auto convert
			MessageRaw messageRaw = new MessageRaw();
			messageRaw.setHost(messageDto.getMessage().getHttpService().getHost());
			messageRaw.setPort(messageDto.getMessage().getHttpService().getPort());
			messageRaw.setProtocol(messageDto.getMessage().getHttpService().getProtocol());
			messageRaw.setRequest(messageDto.getMessage().getRequest());
			messageRaw.setResponse(messageDto.getMessage().getResponse());
			messageRaw.setPrcDate(now);
			messageRawMapper.insert(messageRaw);

			MessageRepeat messageRepeat = new MessageRepeat();
			messageRepeat.setFkMessageId(orgMessageId);
			messageRepeat.setFkMessageRawId(messageRaw.getId());
			messageRepeat.setSendDate(SqlUtil.dateToString(messageDto.getSendDate()));
			messageRepeat.setDifference(messageDto.getDifference());
			messageRepeat.setTime(messageDto.getTime());
			messageRepeat.setStatus(messageDto.getStatus());
			messageRepeat.setLength(messageDto.getLength());
			messageRepeat.setPrcDate(now);
			messageRepeatMapper.insert(messageRepeat);
		});
	}

}
