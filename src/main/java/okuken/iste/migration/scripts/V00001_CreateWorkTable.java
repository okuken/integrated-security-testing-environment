package okuken.iste.migration.scripts;

public class V00001_CreateWorkTable implements PrefixedMigrationScript {
	@Override
	public String getUpScript() {
		return "CREATE TABLE ISTE_WORK(ID INTEGER PRIMARY KEY AUTOINCREMENT, VALUE);";
	}
}
