package okuken.iste.migration.scripts;

public class V00003_ImplRepeatChainFeature implements PrefixedMigrationScript {

	@Override
	public String getUpScript() {
		return  "ALTER TABLE ISTE_MESSAGE_CHAIN_NODE ADD COLUMN MAIN_FLG INTEGER NOT NULL DEFAULT 0;\n" +
				"ALTER TABLE ISTE_MESSAGE_REPEAT ADD COLUMN CHAIN_FLG INTEGER NOT NULL DEFAULT 0;";
	}

}
