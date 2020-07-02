package okuken.iste.logic;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.ibatis.session.SqlSession;
import org.mybatis.dynamic.sql.SqlBuilder;
import org.mybatis.dynamic.sql.select.SelectDSLCompleter;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import okuken.iste.DatabaseManager;
import okuken.iste.dao.MessageMapper;
import okuken.iste.dao.MessageParamMapper;
import okuken.iste.dao.MessageRawDynamicSqlSupport;
import okuken.iste.dao.MessageRawMapper;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageParamDto;
import okuken.iste.entity.Message;
import okuken.iste.entity.MessageParam;
import okuken.iste.entity.MessageRaw;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.SqlUtil;

public class MessageLogic {

	private static final MessageLogic instance = new MessageLogic();
	private MessageLogic() {}
	public static MessageLogic getInstance() {
		return instance;
	}

	public MessageDto convertHttpRequestResponseToDto(IHttpRequestResponse message) { //TODO: externalize to converter
		MessageDto dto = new MessageDto();
		dto.setMessage(message);
		dto.setRequestInfo(BurpUtil.getHelpers().analyzeRequest(message));
		dto.setResponseInfo(BurpUtil.getHelpers().analyzeResponse(message.getResponse()));

		dto.setName(message.getComment());
		dto.setMethod(dto.getRequestInfo().getMethod());
		dto.setUrl(dto.getRequestInfo().getUrl().toExternalForm());
		dto.setParams(dto.getRequestInfo().getParameters().size());
		dto.setStatus(dto.getResponseInfo().getStatusCode());
		dto.setLength(dto.getMessage().getResponse().length);
		dto.setMimeType(dto.getResponseInfo().getStatedMimeType());
		dto.setCookies(dto.getResponseInfo().getCookies().stream()
				.map(cookie -> String.format("%s=%s;", cookie.getName(), cookie.getValue()))
				.collect(Collectors.joining("; ")));

		dto.setMessageParamList(dto.getRequestInfo().getParameters().stream()
				.map(parameter -> convertParameterToDto(parameter)).collect(Collectors.toList()));

		return dto;
	}

	public MessageParamDto convertParameterToDto(IParameter parameter) { //TODO: externalize to converter
		MessageParamDto dto = new MessageParamDto();
		dto.setType(parameter.getType());
		dto.setName(parameter.getName());
		dto.setValue(parameter.getValue());
		return dto;
	}

	public void saveMessages(List<MessageDto> dtos) {
		try {
			String now = SqlUtil.now();
			try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
				MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
				MessageMapper messageMapper = session.getMapper(MessageMapper.class);
				MessageParamMapper messageParamMapper = session.getMapper(MessageParamMapper.class);

				for(MessageDto dto: dtos) {
					MessageRaw messageRaw = new MessageRaw();
					messageRaw.setHost(dto.getMessage().getHttpService().getHost());
					messageRaw.setPort(dto.getMessage().getHttpService().getPort());
					messageRaw.setProtocol(dto.getMessage().getHttpService().getProtocol());
					messageRaw.setRequest(dto.getMessage().getRequest());
					messageRaw.setResponse(dto.getMessage().getResponse());
					messageRaw.setPrcDate(now);
					messageRawMapper.insert(messageRaw); //TODO: generated id is not returned...
					int messageRawId = SqlUtil.loadGeneratedId(session);

					//TODO: auto convert
					Message message = new Message();
					message.setFkProjectId(1);//TODO
					message.setFkMessageRawId(messageRawId);
					message.setName(dto.getName());
					message.setUrl(dto.getUrl());
					message.setMethod(dto.getMethod());
					message.setParams(dto.getParams());
					message.setStatus(dto.getStatus().intValue());
					message.setLength(dto.getLength());
					message.setMimeType(dto.getMimeType());
					message.setCookies(dto.getCookies());
					message.setPrcDate(now);
					messageMapper.insert(message); //TODO: generated id is not returned...
					int messageId = SqlUtil.loadGeneratedId(session);

					for(MessageParamDto paramDto: dto.getMessageParamList()) {
						//TODO: auto convert
						MessageParam messageParam = new MessageParam();
						messageParam.setFkMessageId(messageId);
						messageParam.setType(Byte.toUnsignedInt(paramDto.getType()));
						messageParam.setName(paramDto.getName());
						messageParam.setValue(paramDto.getValue());
						messageParam.setPrcDate(now);
						messageParamMapper.insert(messageParam);
					}
					
				}

				session.commit();
			}
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
		//TODO: rollback controll???
	}

	public List<MessageDto> loadMessages() {
		try {
			List<Message> messages;
			try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
				MessageMapper messageMapper = session.getMapper(MessageMapper.class);
				messages = messageMapper.select(SelectDSLCompleter.allRows());//TODO: where fk_project_id = XXXX
			}

			return messages.stream().map(message -> { //TODO:converter
				MessageDto dto = new MessageDto();
				dto.setName(message.getName());
				dto.setUrl(message.getUrl());
				dto.setMethod(message.getMethod());
				dto.setParams(message.getParams());
				dto.setStatus(message.getStatus().shortValue());
				dto.setLength(message.getLength());
				dto.setMimeType(message.getMimeType());
				dto.setCookies(message.getCookies());
				dto.setMessageRawId(message.getFkMessageRawId());
				return dto;
			}).collect(Collectors.toList());

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public void loadMessageDetail(MessageDto dto) {
		try {
			MessageRaw messageRaw;
			try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
				MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
				messageRaw = messageRawMapper
						.selectOne(c -> c.where(MessageRawDynamicSqlSupport.id, SqlBuilder.isEqualTo(dto.getMessageRawId())))
						.get();
			}

			IHttpRequestResponse httpRequestResponse = BurpUtil.getCallbacks().makeHttpRequest(
					new IHttpService() {
						@Override
						public String getProtocol() { return messageRaw.getProtocol();}
						@Override
						public int getPort() {return messageRaw.getPort();}
						@Override
						public String getHost() {return messageRaw.getHost();}
					},
					messageRaw.getRequest());
			httpRequestResponse.setResponse(messageRaw.getResponse());

			dto.setMessage(httpRequestResponse);
			dto.setRequestInfo(BurpUtil.getHelpers().analyzeRequest(httpRequestResponse)); //TODO: share implementation...
			dto.setResponseInfo(BurpUtil.getHelpers().analyzeResponse(httpRequestResponse.getResponse()));

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

}
