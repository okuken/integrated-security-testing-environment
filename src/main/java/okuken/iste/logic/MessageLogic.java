package okuken.iste.logic;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.mybatis.dynamic.sql.select.CountDSLCompleter;

import com.google.common.collect.Lists;

import burp.IHttpRequestResponse;
import okuken.iste.dao.DatabaseManager;
import okuken.iste.dao.MessageMapper;
import okuken.iste.dao.MessageRawMapper;
import okuken.iste.dto.MessageDto;
import okuken.iste.entity.MessageRaw;
import okuken.iste.util.BurpUtil;

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
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);
//			MessageParamMapper messageParamMapper = session.getMapper(MessageParamMapper.class);

			for(MessageDto dto: dtos) {
				MessageRaw messageRaw = new MessageRaw();
//				messageRaw.setRequest(dto.getHttpRequestResponse().getRequest()); //TODO: bytes
//				messageRaw.setResponse(dto.getHttpRequestResponse().getRequest());
				messageRawMapper.insert(messageRaw);
			}
			
			//TODO: impl
			
		}
	}

	public void loadMessages() {
		//TODO:impl
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);
			BurpUtil.printEventLog("hoge" + messageMapper.count(CountDSLCompleter.allRows())); // or c->c
		}
	}

}
