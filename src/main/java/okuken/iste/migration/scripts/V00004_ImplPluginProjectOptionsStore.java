package okuken.iste.migration.scripts;

public class V00004_ImplPluginProjectOptionsStore implements PrefixedMigrationScript {

	@Override
	public String getUpScript() {
		return  "CREATE TABLE ISTE_PLUGIN_PROJECT_OPTION (\n" + 
				"  ID             INTEGER PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID  INTEGER NOT NULL,\n" + 
				"  PLUGIN_NAME    TEXT    NOT NULL,\n" +
				"  KEY            TEXT    NOT NULL,\n" + 
				"  VAL            TEXT,\n" + 
				"  PRC_DATE       TEXT    NOT NULL,\n" + 
				"  UNIQUE(FK_PROJECT_ID, PLUGIN_NAME, KEY),\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID)\n" + 
				");";
	}

}
