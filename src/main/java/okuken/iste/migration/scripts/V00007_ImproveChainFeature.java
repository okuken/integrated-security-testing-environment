package okuken.iste.migration.scripts;

public class V00007_ImproveChainFeature implements PrefixedMigrationScript {

	@Override
	public String getUpScript() {
		return  "CREATE TABLE ISTE_MESSAGE_CHAIN_PRE_VAR (\n" + 
				"  ID                  INTEGER PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_CHAIN_ID INTEGER NOT NULL,\n" + 
				"  NAME                TEXT    NOT NULL,\n" + 
				"  VALUE               TEXT,\n" + 
				"  PRC_DATE            TEXT    NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_CHAIN_ID) REFERENCES ISTE_MESSAGE_CHAIN(ID)\n" + 
				");\n"+
				"\n"+
				"ALTER TABLE ISTE_MESSAGE_CHAIN_NODE ADD COLUMN BREAKPOINT INTEGER default 0 NOT NULL;";
	}

}
