package okuken.iste.migration.scripts;

import org.apache.ibatis.migration.BootstrapScript;

import okuken.iste.migration.DatabaseMigrator;

public class Bootstrap implements BootstrapScript {

	@Override
	public String getScript() {
		return  "CREATE TABLE " + DatabaseMigrator.CHANGELOG_TABLE_NAME + " (\n" + 
				"  ID          INTEGER PRIMARY KEY,\n" + 
				"  APPLIED_AT  TEXT    NOT NULL,\n" + 
				"  DESCRIPTION TEXT    NOT NULL\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_USER (\n" + 
				"  ID       INTEGER PRIMARY KEY AUTOINCREMENT,\n" + 
				"  NAME     TEXT    NOT NULL UNIQUE,\n" + 
				"  PRC_DATE TEXT    NOT NULL \n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_PROJECT (\n" + 
				"  ID          INTEGER PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_USER_ID  INTEGER NOT NULL,\n" + 
				"  NAME        TEXT    NOT NULL UNIQUE,\n" + 
				"  EXPLANATION TEXT,\n" + 
				"  PRC_DATE    TEXT    NOT NULL,\n" + 
				"  FOREIGN KEY(FK_USER_ID) REFERENCES ISTE_USER(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_RAW (\n" + 
				"  ID       INTEGER PRIMARY KEY AUTOINCREMENT,\n" + 
				"  HOST     TEXT    NOT NULL,\n" + 
				"  PORT     INTEGER NOT NULL,\n" + 
				"  PROTOCOL TEXT    NOT NULL,\n" + 
				"  REQUEST  BLOB    NOT NULL,\n" + 
				"  RESPONSE BLOB,\n" + 
				"  PRC_DATE TEXT    NOT NULL\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE (\n" + 
				"  ID                INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID     INTEGER  NOT NULL,\n" + 
				"  FK_MESSAGE_RAW_ID INTEGER  NOT NULL,\n" + 
				"  NAME              TEXT,\n" + 
				"  REMARK            TEXT,\n" + 
				"  AUTH_MATRIX       TEXT,\n" + 
				"  PRIORITY          TEXT,\n" + 
				"  PROGRESS          INTEGER  NOT NULL,\n" + 
				"  PROGRESS_MEMO     TEXT,\n" + 
				"  PROGRESS_EXT01    TEXT,\n" + 
				"  PROGRESS_EXT02    TEXT,\n" + 
				"  PROGRESS_EXT03    TEXT,\n" + 
				"  PROGRESS_EXT04    TEXT,\n" + 
				"  PROGRESS_EXT05    TEXT,\n" + 
				"  PROGRESS_EXT06    TEXT,\n" + 
				"  PROGRESS_EXT07    TEXT,\n" + 
				"  PROGRESS_EXT08    TEXT,\n" + 
				"  PROGRESS_EXT09    TEXT,\n" + 
				"  PROGRESS_EXT10    TEXT,\n" + 
				"  URL               TEXT     NOT NULL,\n" + 
				"  METHOD            TEXT     NOT NULL,\n" + 
				"  PARAMS            INTEGER  NOT NULL,\n" + 
				"  STATUS            INTEGER,\n" + 
				"  LENGTH            INTEGER,\n" + 
				"  MIME_TYPE         TEXT,\n" + 
				"  COOKIES           TEXT,\n" + 
				"  DELETE_FLG        INTEGER  NOT NULL,\n" + 
				"  PRC_DATE          TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID),\n" + 
				"  FOREIGN KEY(FK_MESSAGE_RAW_ID) REFERENCES ISTE_MESSAGE_RAW(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_PARAM (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_ID INTEGER  NOT NULL,\n" + 
				"  TYPE          INTEGER  NOT NULL,\n" + 
				"  NAME          TEXT     NOT NULL,\n" + 
				"  VALUE         TEXT,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_ID) REFERENCES ISTE_MESSAGE(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_ORD (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID INTEGER  NOT NULL,\n" + 
				"  ORD           TEXT     NOT NULL,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_REPEAT (\n" + 
				"  ID                INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_ID     INTEGER  NOT NULL,\n" + 
				"  FK_MESSAGE_RAW_ID INTEGER  NOT NULL,\n" + 
				"  SEND_DATE         TEXT     NOT NULL,\n" + 
				"  DIFFERENCE        TEXT,\n" + 
				"  USER_ID           TEXT,\n" + 
				"  TIME              INTEGER,\n" + 
				"  STATUS            INTEGER,\n" + 
				"  LENGTH            INTEGER,\n" + 
				"  MEMO              TEXT,\n" + 
				"  PRC_DATE          TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_ID) REFERENCES ISTE_MESSAGE(ID),\n" + 
				"  FOREIGN KEY(FK_MESSAGE_RAW_ID) REFERENCES ISTE_MESSAGE_RAW(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_REPEAT_REDIR (\n" + 
				"  ID                   INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_REPEAT_ID INTEGER  NOT NULL,\n" + 
				"  FK_MESSAGE_RAW_ID    INTEGER  NOT NULL,\n" + 
				"  SEND_DATE            TEXT     NOT NULL,\n" + 
				"  TIME                 INTEGER,\n" + 
				"  STATUS               INTEGER,\n" + 
				"  LENGTH               INTEGER,\n" + 
				"  PRC_DATE             TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_REPEAT_ID) REFERENCES ISTE_MESSAGE_REPEAT(ID),\n" + 
				"  FOREIGN KEY(FK_MESSAGE_RAW_ID) REFERENCES ISTE_MESSAGE_RAW(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_REPEAT_MASTER (\n" + 
				"  ID                INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_ID     INTEGER  NOT NULL,\n" + 
				"  FK_MESSAGE_RAW_ID INTEGER  NOT NULL,\n" + 
				"  PRC_DATE          TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_ID) REFERENCES ISTE_MESSAGE(ID),\n" + 
				"  FOREIGN KEY(FK_MESSAGE_RAW_ID) REFERENCES ISTE_MESSAGE_RAW(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_CHAIN (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_ID INTEGER,\n" + 
				"  NODE_ORDER    TEXT,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_ID) REFERENCES ISTE_MESSAGE(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_CHAIN_NODE (\n" + 
				"  ID                  INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_CHAIN_ID INTEGER  NOT NULL,\n" + 
				"  FK_MESSAGE_ID       INTEGER  NOT NULL,\n" + 
				"  PRC_DATE            TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_CHAIN_ID) REFERENCES ISTE_MESSAGE_CHAIN(ID),\n" + 
				"  FOREIGN KEY(FK_MESSAGE_ID) REFERENCES ISTE_MESSAGE(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_CHAIN_NODE_IN (\n" + 
				"  ID                       INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_CHAIN_NODE_ID INTEGER  NOT NULL,\n" + 
				"  PARAM_TYPE               INTEGER  NOT NULL,\n" + 
				"  PARAM_NAME               TEXT     NOT NULL,\n" + 
				"  VAR_NAME                 TEXT,\n" + 
				"  PRC_DATE                 TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_CHAIN_NODE_ID) REFERENCES ISTE_MESSAGE_CHAIN_NODE(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MESSAGE_CHAIN_NODE_OUT (\n" + 
				"  ID                       INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_CHAIN_NODE_ID INTEGER  NOT NULL,\n" + 
				"  PARAM_TYPE               INTEGER  NOT NULL,\n" + 
				"  PARAM_NAME               TEXT,\n" + 
				"  REGEX                    TEXT,\n" + 
				"  VAR_NAME                 TEXT     NOT NULL,\n" + 
				"  PRC_DATE                 TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_CHAIN_NODE_ID) REFERENCES ISTE_MESSAGE_CHAIN_NODE(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_AUTH_ACCOUNT (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID INTEGER  NOT NULL,\n" + 
				"  USER_ID       TEXT,\n" + 
				"  PASSWORD      TEXT,\n" + 
				"  REMARK        TEXT,\n" + 
				"  SESSION_ID    TEXT,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_AUTH_CONFIG (\n" + 
				"  ID                  INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID       INTEGER  NOT NULL,\n" + 
				"  FK_MESSAGE_CHAIN_ID INTEGER  NOT NULL,\n" + 
				"  PRC_DATE            TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID),\n" + 
				"  FOREIGN KEY(FK_MESSAGE_CHAIN_ID) REFERENCES ISTE_MESSAGE_CHAIN(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_PROJECT_OPTION (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID INTEGER  NOT NULL,\n" + 
				"  KEY           TEXT     NOT NULL,\n" + 
				"  VAL           TEXT,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MEMO_PROJECT (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_PROJECT_ID INTEGER  NOT NULL,\n" + 
				"  MEMO          TEXT,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_PROJECT_ID) REFERENCES ISTE_PROJECT(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MEMO_MESSAGE (\n" + 
				"  ID            INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_ID INTEGER  NOT NULL  UNIQUE,\n" + 
				"  MEMO          TEXT,\n" + 
				"  PRC_DATE      TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_ID) REFERENCES ISTE_MESSAGE(ID)\n" + 
				");\n" + 
				"\n" + 
				"CREATE TABLE ISTE_MEMO_MESSAGE_PARAM (\n" + 
				"  ID                  INTEGER  PRIMARY KEY AUTOINCREMENT,\n" + 
				"  FK_MESSAGE_PARAM_ID INTEGER  NOT NULL  UNIQUE,\n" + 
				"  MEMO                TEXT,\n" + 
				"  PRC_DATE            TEXT     NOT NULL,\n" + 
				"  FOREIGN KEY(FK_MESSAGE_PARAM_ID) REFERENCES ISTE_MESSAGE_PARAM(ID)\n" + 
				");";
	}

}
