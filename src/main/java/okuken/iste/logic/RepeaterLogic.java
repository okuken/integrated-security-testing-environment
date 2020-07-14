package okuken.iste.logic;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.mybatis.dynamic.sql.SqlBuilder;

import burp.IHttpRequestResponse;
import okuken.iste.dao.MessageRawMapper;
import okuken.iste.dao.MessageRepeatDynamicSqlSupport;
import okuken.iste.dao.MessageRepeatMapper;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRepeatDto;
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

	public MessageRepeatDto sendRequest(byte[] request, MessageDto orgMessageDto) {
		try {
			Date sendDate = Calendar.getInstance().getTime();
			long timerStart = System.currentTimeMillis();

			IHttpRequestResponse response = BurpUtil.getCallbacks().makeHttpRequest(
					orgMessageDto.getMessage().getHttpService(),
					request);

			long timerEnd = System.currentTimeMillis();
			int time = (int) (timerEnd - timerStart);

			MessageRepeatDto ret = new MessageRepeatDto();
			ret.setMessage(response);
			ret.setStatus(BurpUtil.getHelpers().analyzeResponse(response.getResponse()).getStatusCode());
			ret.setLength(response.getResponse().length);
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

	private void save(MessageRepeatDto messageRepeatDto, Integer orgMessageId) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
			MessageRepeatMapper messageRepeatMapper = session.getMapper(MessageRepeatMapper.class);

			//TODO: auto convert
			MessageRaw messageRaw = new MessageRaw();
			messageRaw.setHost(messageRepeatDto.getMessage().getHttpService().getHost());
			messageRaw.setPort(messageRepeatDto.getMessage().getHttpService().getPort());
			messageRaw.setProtocol(messageRepeatDto.getMessage().getHttpService().getProtocol());
			messageRaw.setRequest(messageRepeatDto.getMessage().getRequest());
			messageRaw.setResponse(messageRepeatDto.getMessage().getResponse());
			messageRaw.setPrcDate(now);
			messageRawMapper.insert(messageRaw);

			MessageRepeat messageRepeat = new MessageRepeat();
			messageRepeat.setFkMessageId(orgMessageId);
			messageRepeat.setFkMessageRawId(messageRaw.getId());
			messageRepeat.setSendDate(SqlUtil.dateToString(messageRepeatDto.getSendDate()));
			messageRepeat.setDifference(messageRepeatDto.getDifference());
			messageRepeat.setTime(messageRepeatDto.getTime());
			messageRepeat.setStatus(messageRepeatDto.getStatus());
			messageRepeat.setLength(messageRepeatDto.getLength());
			messageRepeat.setPrcDate(now);
			messageRepeatMapper.insert(messageRepeat);
		});
	}

	public List<MessageRepeatDto> loadHistory(Integer orgMessageId) {
		try {
			List<MessageRepeat> messageRepeats = 
				DbUtil.withSession(session -> {
					MessageRepeatMapper messageRepeatMapper = session.getMapper(MessageRepeatMapper.class);
					return messageRepeatMapper.select(c -> c
							.where(MessageRepeatDynamicSqlSupport.fkMessageId, SqlBuilder.isEqualTo(orgMessageId))
							.orderBy(MessageRepeatDynamicSqlSupport.id));
				});

			return messageRepeats.stream().map(messageRepeat -> { //TODO:converter
				MessageRepeatDto dto = new MessageRepeatDto();
				dto.setOrgMessageId(messageRepeat.getFkMessageId());
				dto.setMessageRawId(messageRepeat.getFkMessageRawId());
				dto.setSendDate(SqlUtil.stringToDate(messageRepeat.getSendDate()));
				dto.setDifference(messageRepeat.getDifference());
				dto.setTime(messageRepeat.getTime());
				dto.setStatus(messageRepeat.getStatus());
				dto.setLength(messageRepeat.getLength());
				return dto;
			}).collect(Collectors.toList());

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

}
