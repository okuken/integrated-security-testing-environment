package okuken.iste.dto;

public class UserOptionsDto {

	private String userName;
	private String dbFilePath;
	private String lastSelectedProjectName;

	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getDbFilePath() {
		return dbFilePath;
	}
	public void setDbFilePath(String dbFilePath) {
		this.dbFilePath = dbFilePath;
	}
	public String getLastSelectedProjectName() {
		return lastSelectedProjectName;
	}
	public void setLastSelectedProjectName(String lastSelectedProjectName) {
		this.lastSelectedProjectName = lastSelectedProjectName;
	}

}
