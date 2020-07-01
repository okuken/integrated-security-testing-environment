package okuken.iste.logic;

import java.sql.Date;
import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.mybatis.dynamic.sql.select.CountDSLCompleter;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;
import okuken.iste.DatabaseManager;
import okuken.iste.dao.MessageMapper;
import okuken.iste.dao.MessageParamMapper;
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

	public List<MessageDto> convertHttpRequestResponsesToDtos(IHttpRequestResponse[] messages) {
		List<MessageDto> ret = Lists.newArrayList();
		for(IHttpRequestResponse message: messages) {
			ret.add(MessageDto.create(message, message.getComment()));
		}
		return ret;
	}

	public void saveMessages(List<MessageDto> dtos) {
		Date now = SqlUtil.now();
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);
			MessageParamMapper messageParamMapper = session.getMapper(MessageParamMapper.class);

			for(MessageDto dto: dtos) {
				MessageRaw messageRaw = new MessageRaw();
				messageRaw.setRequest(dto.getHttpRequestResponse().getRequest());
				messageRaw.setResponse(dto.getHttpRequestResponse().getResponse());
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
		//TODO: rollback controll???
	}

	public void loadMessages() {
		//TODO:impl
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);
			BurpUtil.printEventLog("hoge" + messageMapper.count(CountDSLCompleter.allRows())); // or c->c
		}
	}

}
