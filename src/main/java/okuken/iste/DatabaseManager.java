package okuken.iste;

import java.io.IOException;
import java.util.Arrays;

import org.apache.ibatis.datasource.pooled.PooledDataSource;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.migration.ConnectionProvider;
import org.apache.ibatis.migration.JdbcConnectionProvider;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;

import com.google.common.reflect.ClassPath;

import okuken.iste.migration.DatabaseMigrator;

public class DatabaseManager {

	private static final DatabaseManager instance = new DatabaseManager();

	private static final String DRIVER = "org.sqlite.JDBC";
	private static final String URL_PREFIX = "jdbc:sqlite:";

	private String sqliteDbFilePath;
	private PooledDataSource dataSource;
	private SqlSessionFactory sqlSessionFactory;

	private DatabaseManager() {}
	public static DatabaseManager getInstance() {
		return instance;
	}

	public void setupDatabase(String sqliteDbFilePath) {
		this.sqliteDbFilePath = sqliteDbFilePath.replaceAll("\\\\", "/");
		this.dataSource = createDataSource();
		this.sqlSessionFactory = createSqlSessionFactory();
		DatabaseMigrator.getInstance().migrate(createConnectionProvider());
	}

	private PooledDataSource createDataSource() {
		PooledDataSource ret = new PooledDataSource();
		ret.setDriver(DRIVER);
		ret.setUrl(URL_PREFIX + sqliteDbFilePath);
		return ret;
	}

	private ConnectionProvider createConnectionProvider() {
		try {
			return new JdbcConnectionProvider(DRIVER, URL_PREFIX + sqliteDbFilePath, null, null);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private SqlSessionFactory createSqlSessionFactory() {
		Configuration configuration = new Configuration(
				new Environment("prod", new JdbcTransactionFactory(), this.dataSource));
		addAllMappers(configuration);
		return new SqlSessionFactoryBuilder().build(configuration);
	}
	private void addAllMappers(Configuration configuration) {
		try {
			ClassLoader loader = this.getClass().getClassLoader();
			for(String packageName: Arrays.asList("okuken.iste.dao.auto", "okuken.iste.dao")) {
				ClassPath.from(loader).getTopLevelClasses(packageName).stream()
					.filter(classInfo -> classInfo.getName().endsWith("Mapper"))
					.map(classInfo -> classInfo.load())
					.forEach(clazz -> configuration.addMapper(clazz));
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void changeDatabase(String sqliteDbFilePath) {
		unloadDatabase();
		setupDatabase(sqliteDbFilePath);
	}

	public void unloadDatabase() {
		dataSource.forceCloseAll();
	}

	public SqlSessionFactory getSessionFactory() {
		return sqlSessionFactory;
	}

}
