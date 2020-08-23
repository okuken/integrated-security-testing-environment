package okuken.iste.migration.scripts;

import java.math.BigDecimal;

import org.apache.ibatis.migration.MigrationScript;

public interface PrefixedMigrationScript extends MigrationScript {

	static int VERSION_NUMBER_LENGTH = 5;

	@Override
	default BigDecimal getId() {
		return new BigDecimal(getClass().getSimpleName().substring(1, VERSION_NUMBER_LENGTH + 1));
	}

	@Override
	default String getDescription() {
		return getClass().getName();
	}

	@Override
	default String getDownScript() {
		throw new UnsupportedOperationException();
	}

}
