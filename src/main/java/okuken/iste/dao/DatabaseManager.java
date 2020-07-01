package okuken.iste.dao;

import java.io.IOException;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.ibatis.datasource.pooled.PooledDataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;

import com.google.common.reflect.ClassPath;

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
		addAllMappers(configuration);
		return new SqlSessionFactoryBuilder().build(configuration);
	}
	private void addAllMappers(Configuration configuration) {
		try {
			ClassLoader loader = Thread.currentThread().getContextClassLoader();
			ClassPath.from(loader).getTopLevelClasses("okuken.iste.dao").stream()
					.filter(classInfo -> classInfo.getName().endsWith("Mapper"))
					.map(classInfo -> classInfo.load())
					.forEach(clazz -> configuration.addMapper(clazz));
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
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
