package okuken.iste.migration.scripts;

public class V00001_ImplMessageChainFeature implements PrefixedMigrationScript {

	@Override
	public String getUpScript() {
		return  "ALTER TABLE ISTE_MESSAGE_CHAIN_NODE_IN RENAME TO ISTE_MESSAGE_CHAIN_NODE_REQP;\n" +
				"ALTER TABLE ISTE_MESSAGE_CHAIN_NODE_REQP ADD COLUMN SOURCE_TYPE INTEGER;\n" + 
				"ALTER TABLE ISTE_MESSAGE_CHAIN_NODE_REQP RENAME COLUMN VAR_NAME TO SOURCE_NAME;\n" + 
				"\n" + 
				"ALTER TABLE ISTE_MESSAGE_CHAIN_NODE_OUT RENAME TO ISTE_MESSAGE_CHAIN_NODE_RESP;\n" +
				"\n" + 
				"ALTER TABLE ISTE_AUTH_ACCOUNT RENAME COLUMN USER_ID TO FIELD01;\n" + 
				"ALTER TABLE ISTE_AUTH_ACCOUNT RENAME COLUMN PASSWORD TO FIELD02;\n" + 
				"ALTER TABLE ISTE_AUTH_ACCOUNT ADD COLUMN FIELD03 TEXT;\n" + 
				"ALTER TABLE ISTE_AUTH_ACCOUNT ADD COLUMN FIELD04 TEXT;\n" + 
				"ALTER TABLE ISTE_AUTH_ACCOUNT ADD COLUMN FIELD05 TEXT;";
	}

}
