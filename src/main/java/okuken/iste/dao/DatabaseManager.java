package okuken.iste.dao;

import java.sql.SQLException;
import java.sql.Statement;

import org.apache.ibatis.datasource.pooled.PooledDataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;

public class DatabaseManager {

	private static final DatabaseManager instance = new DatabaseManager();

	private PooledDataSource dataSource;
	private SqlSessionFactory sqlSessionFactory;

	private DatabaseManager() {}
	public static DatabaseManager getInstance() {
		return instance;
	}

	public void setupDatabase(String sqliteDbFilePath) {
		try {
			this.dataSource = createDataSource(sqliteDbFilePath);
			this.sqlSessionFactory = createSqlSessionFactory();
			if (judgeIsNeedInitDatabase()) {
				initDatabase();
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}

	private PooledDataSource createDataSource(String sqliteDbFilePath) {
		PooledDataSource ret = new PooledDataSource();
		ret.setDriver("org.sqlite.JDBC");
		ret.setUrl("jdbc:sqlite:" + sqliteDbFilePath);
		return ret;
	}

	private SqlSessionFactory createSqlSessionFactory() {
		Configuration configuration = new Configuration(
				new Environment("prod", new JdbcTransactionFactory(), this.dataSource));
		configuration.addMapper(MessageMapper.class); // TODO: auto load
		return new SqlSessionFactoryBuilder().build(configuration);
	}

	private boolean judgeIsNeedInitDatabase() {
		return true; //TODO:impl
	}
	private void initDatabase() throws SQLException {
		//TODO: impl
		try (SqlSession session = sqlSessionFactory.openSession()) {
			try (Statement stmt = session.getConnection().createStatement()) {
				stmt.execute(
						"CREATE TABLE IF NOT EXISTS STM_MSG (ID INTEGER, NAME TEXT, URL TEXT)");
			}
		}
	}

	public void unloadDatabase() {
		dataSource.forceCloseAll();
	}

	public SqlSessionFactory getSessionFactory() {
		return sqlSessionFactory;
	}

}
