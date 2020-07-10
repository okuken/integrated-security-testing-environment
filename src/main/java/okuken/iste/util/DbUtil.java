package okuken.iste.util;

import java.util.function.Consumer;
import java.util.function.Function;

import org.apache.ibatis.session.SqlSession;

import okuken.iste.DatabaseManager;

public class DbUtil {

	public static final void withTransaction(Consumer<SqlSession> consumer) {
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			try {
				consumer.accept(session);
				session.commit();
			} catch(Exception e) {
				session.rollback();
				throw e;
			}
		}
	}

	public static final <T> T withSession(Function<SqlSession, T> function) {
		try (SqlSession session = DatabaseManager.getInstance().getSessionFactory().openSession()) {
			try {
				return function.apply(session);
			} catch(Exception e) {
				throw e;
			}
		}
	}

}
