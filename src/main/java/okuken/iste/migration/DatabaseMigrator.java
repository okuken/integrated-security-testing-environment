package okuken.iste.migration;

import java.io.PrintStream;

import org.apache.ibatis.migration.ConnectionProvider;
import org.apache.ibatis.migration.MigrationLoader;
import org.apache.ibatis.migration.operations.BootstrapOperation;
import org.apache.ibatis.migration.operations.StatusOperation;
import org.apache.ibatis.migration.operations.UpOperation;
import org.apache.ibatis.migration.options.DatabaseOperationOption;

import okuken.iste.consts.Captions;
import okuken.iste.util.UiUtil;

public class DatabaseMigrator {

	private static final DatabaseMigrator instance = new DatabaseMigrator();
	private DatabaseMigrator() {}
	public static DatabaseMigrator getInstance() {
		return instance;
	}

	public static final String CHANGELOG_TABLE_NAME = "ISTE_MIGRATE_CHANGELOG";

	public void migrate(ConnectionProvider connectionProvider) {
		var migrationsLoader = createMigrationsLoader();
		var databaseOperationOption = createDatabaseOperationOption();
		var logStream = System.out;

		var status = new StatusOperation().operate(connectionProvider, migrationsLoader, databaseOperationOption, new PrintStream(System.out));
		if(status.getAppliedCount() <= 0) { // case: before initialization
			new BootstrapOperation().operate(connectionProvider, migrationsLoader, databaseOperationOption, logStream);
			new UpOperation().operate(connectionProvider, migrationsLoader, databaseOperationOption, logStream);
			return;
		}

		if(status.getPendingCount() > 0 && UiUtil.getConfirmAnswer(Captions.MESSAGE_MIGRATION)) {
			new UpOperation().operate(connectionProvider, migrationsLoader, databaseOperationOption, logStream);
		}
	}

	private MigrationLoader createMigrationsLoader() {
		return new JavaMigrationLoaderForJar(this.getClass().getClassLoader(), this.getClass().getPackageName() + ".scripts");
	}

	private DatabaseOperationOption createDatabaseOperationOption() {
		var ret = new DatabaseOperationOption();
		ret.setChangelogTable(CHANGELOG_TABLE_NAME);
		return ret;
	}

}
