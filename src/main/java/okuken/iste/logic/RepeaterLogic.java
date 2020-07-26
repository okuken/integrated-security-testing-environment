package okuken.iste.logic;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.mybatis.dynamic.sql.BasicColumn;
import org.mybatis.dynamic.sql.SqlBuilder;
import org.mybatis.dynamic.sql.SqlColumn;
import org.mybatis.dynamic.sql.render.RenderingStrategies;
import org.mybatis.dynamic.sql.select.render.SelectStatementProvider;

import burp.IHttpRequestResponse;
import burp.IParameter;
import okuken.iste.dao.auto.MessageRawMapper;
import okuken.iste.dao.auto.MessageRepeatDynamicSqlSupport;
import okuken.iste.dao.MessageRepeatMapper;
import okuken.iste.dao.auto.MessageRepeatRedirDynamicSqlSupport;
import okuken.iste.dao.auto.MessageRepeatRedirMapper;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRepeatDto;
import okuken.iste.dto.MessageRepeatRedirectDto;
import okuken.iste.dto.PayloadDto;
import okuken.iste.entity.auto.MessageRaw;
import okuken.iste.entity.MessageRepeat;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.DbUtil;
import okuken.iste.util.HttpUtil;
import okuken.iste.util.SqlUtil;

public class RepeaterLogic {

	private static final RepeaterLogic instance = new RepeaterLogic();
	private RepeaterLogic() {}
	public static RepeaterLogic getInstance() {
		return instance;
	}

	public MessageRepeatDto sendRequest(List<PayloadDto> payloadDtos, MessageDto orgMessageDto, boolean needSaveHistory) {
		try {
			return sendRequest(
					applyPayloads(orgMessageDto.getMessage().getRequest(), payloadDtos),
					null,
					orgMessageDto,
					needSaveHistory);

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}
	private byte[] applyPayloads(byte[] request, List<PayloadDto> payloadDtos) {
		byte[] ret = request;
		for(PayloadDto payloadDto: payloadDtos) {
			ret = BurpUtil.getHelpers().updateParameter(ret, BurpUtil.getHelpers().buildParameter(
					payloadDto.getTargetParamName(),
					payloadDto.getPayload(),
					payloadDto.getTargetParamType()));
		}
		return ret;
	}

	public MessageRepeatDto sendRequest(byte[] aRequest, AuthAccountDto authAccountDto, MessageDto orgMessageDto, boolean needSaveHistory) {
		try {
			byte[] request = aRequest;
			if(authAccountDto != null && authAccountDto.getSessionId() != null) {
				AuthConfigDto authConfig = ConfigLogic.getInstance().getAuthConfig();
				if(authConfig == null) {
					throw new IllegalStateException("Sessionid was set but AuthConfig has not saved.");
				}
				var sessionidNodeOutDto = authConfig.getAuthMessageChainDto().getNodes().get(0).getOuts().get(0);

				IParameter sessionIdParam = BurpUtil.getHelpers().buildParameter(
						sessionidNodeOutDto.getParamName(),
						authAccountDto.getSessionId(),
						sessionidNodeOutDto.getParamType());

				request = BurpUtil.getHelpers().removeParameter(request, sessionIdParam);
				request = HttpUtil.removeDustAtEndOfCookieHeader(request); // bug recovery
				request = BurpUtil.getHelpers().addParameter(request, sessionIdParam);
			}

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

			if(needSaveHistory) {
				save(ret, authAccountDto, orgMessageDto);
			}

			return ret;

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	private void save(MessageRepeatDto messageRepeatDto, AuthAccountDto authAccountDto, MessageDto orgMessageDto) {
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
			messageRepeat.setFkMessageId(orgMessageDto.getId());
			messageRepeat.setFkMessageRawId(messageRaw.getId());
			messageRepeat.setSendDate(SqlUtil.dateToString(messageRepeatDto.getSendDate()));
			messageRepeat.setDifference(messageRepeatDto.getDifference());
			if(authAccountDto != null && authAccountDto.getSessionId() != null) {
				messageRepeat.setUserId(authAccountDto.getUserId());
			}
			messageRepeat.setTime(messageRepeatDto.getTime());
			messageRepeat.setStatus(messageRepeatDto.getStatus());
			messageRepeat.setLength(messageRepeatDto.getLength());
			messageRepeat.setPrcDate(now);
			messageRepeatMapper.insert(messageRepeat);
			messageRepeatDto.setId(messageRepeat.getId());

			orgMessageDto.addRepeat(messageRepeatDto);
		});
	}

	public void updateMemo(MessageRepeatDto messageRepeatDto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageRepeatMapper messageRepeatMapper = session.getMapper(MessageRepeatMapper.class);

			MessageRepeat messageRepeat = new MessageRepeat();
			messageRepeat.setId(messageRepeatDto.getId());
			messageRepeat.setMemo(messageRepeatDto.getMemo());
			messageRepeat.setPrcDate(now);
			messageRepeatMapper.updateByPrimaryKeySelective(messageRepeat);
		});
	}

	public List<MessageRepeatDto> loadHistory(Integer orgMessageId) {
		try {
			List<MessageRepeat> messageRepeats = 
				DbUtil.withSession(session -> {
					var messageRepeatMapper = session.getMapper(MessageRepeatMapper.class);
					SelectStatementProvider selectStatement = SqlBuilder
									.select(ArrayUtils.addAll(
										Arrays.stream(MessageRepeatMapper.selectList).map(c->c.as(((SqlColumn<?>)c).name())).collect(Collectors.toList()).toArray(new BasicColumn[0]),
										Arrays.stream(MessageRepeatRedirMapper.selectList).map(c->c.as("mrr_" + ((SqlColumn<?>)c).name())).collect(Collectors.toList()).toArray(new BasicColumn[0])))
									.from(MessageRepeatDynamicSqlSupport.messageRepeat)
									.leftJoin(MessageRepeatRedirDynamicSqlSupport.messageRepeatRedir).on(MessageRepeatDynamicSqlSupport.messageRepeat.id, SqlBuilder.equalTo(MessageRepeatRedirDynamicSqlSupport.messageRepeatRedir.fkMessageRepeatId))
									.where(MessageRepeatDynamicSqlSupport.fkMessageId, SqlBuilder.isEqualTo(orgMessageId))
									.orderBy(MessageRepeatDynamicSqlSupport.id)
									.build()
									.render(RenderingStrategies.MYBATIS3);

					return messageRepeatMapper.selectManyWithRedir(selectStatement);
				});

			return messageRepeats.stream().map(messageRepeat -> { //TODO:converter
				MessageRepeatDto dto = new MessageRepeatDto();
				dto.setId(messageRepeat.getId());
				dto.setOrgMessageId(messageRepeat.getFkMessageId());
				dto.setMessageRawId(messageRepeat.getFkMessageRawId());
				dto.setSendDate(SqlUtil.stringToDate(messageRepeat.getSendDate()));
				dto.setDifference(messageRepeat.getDifference());
				dto.setUserId(messageRepeat.getUserId());
				dto.setTime(messageRepeat.getTime());
				dto.setStatus(messageRepeat.getStatus());
				dto.setLength(messageRepeat.getLength());
				dto.setMemo(messageRepeat.getMemo());

				dto.setMessageRepeatRedirectDtos(
					messageRepeat.getMessageRepeatRedirs().stream().map(redirect -> {
						var redirectDto = new MessageRepeatRedirectDto();
						redirectDto.setId(redirect.getId());
						redirectDto.setSendDate(SqlUtil.stringToDate(redirect.getSendDate()));
						redirectDto.setStatus(redirect.getStatus());
						redirectDto.setLength(redirect.getLength());
						redirectDto.setTime(redirect.getTime());
						redirectDto.setMessageRawId(redirect.getFkMessageRawId());
						return redirectDto;
					}).collect(Collectors.toList()));

				return dto;
			}).collect(Collectors.toList());

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

}
