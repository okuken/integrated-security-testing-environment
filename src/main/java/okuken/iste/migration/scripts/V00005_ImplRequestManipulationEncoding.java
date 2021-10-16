package okuken.iste.migration.scripts;

public class V00005_ImplRequestManipulationEncoding implements PrefixedMigrationScript {

	@Override
	public String getUpScript() {
		return "ALTER TABLE ISTE_MESSAGE_CHAIN_NODE_REQP ADD COLUMN ENCODE TEXT;";
	}

}
