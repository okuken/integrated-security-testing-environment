package okuken.iste.migration.scripts;

public class V00002_CreateWorkTable2 implements PrefixedMigrationScript {
	@Override
	public String getUpScript() {
		return "CREATE TABLE ISTE_WORK2(ID INTEGER PRIMARY KEY AUTOINCREMENT, VALUE);";
	}
}
