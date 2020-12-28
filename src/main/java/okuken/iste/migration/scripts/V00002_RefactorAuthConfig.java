package okuken.iste.migration.scripts;

public class V00002_RefactorAuthConfig implements PrefixedMigrationScript {

	@Override
	public String getUpScript() {
		return  "CREATE TABLE ISTE_AUTH_APPLY_CONFIG (\n" + 
				"  ID                INTEGER PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_AUTH_CONFIG_ID INTEGER NOT NULL,\n" + 
				"  PARAM_TYPE        INTEGER NOT NULL,\n" + 
				"  PARAM_NAME        TEXT    NOT NULL,\n" + 
				"  VAR_NAME          TEXT    NOT NULL,\n" + 
				"  PRC_DATE          TEXT    NOT NULL,\n" + 
				"  FOREIGN KEY(FK_AUTH_CONFIG_ID) REFERENCES ISTE_AUTH_CONFIG(ID)\n" + 
				");";
	}

}
