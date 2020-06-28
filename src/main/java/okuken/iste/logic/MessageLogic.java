package okuken.iste.logic;

import org.apache.ibatis.session.SqlSession;

import burp.IHttpRequestResponse;
import okuken.iste.dao.DatabaseManager;
import okuken.iste.dao.MessageDao;
import okuken.iste.util.BurpUtil;

public class MessageLogic {

	private static final MessageLogic instance = new MessageLogic();
	private MessageLogic() {}
	public static MessageLogic getInstance() {
		return instance;
	}

	public void saveMessages(IHttpRequestResponse[] messages) {
		//TODO:impl
	}

	public void loadMessages() {
		//TODO:impl
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			  MessageDao messageDao = session.getMapper(MessageDao.class);
			  BurpUtil.printEventLog("hoge" + messageDao.getCount());
		}
	}

}
