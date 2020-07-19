package okuken.iste.dto;

public class AuthConfigDto {

	private String sessionIdParamName;
	private byte sessionIdParamType; //@see IParameter

	private AuthAccountDto selectedAuthAccountDto;


	public String getSessionIdParamName() {
		return sessionIdParamName;
	}
	public void setSessionIdParamName(String sessionIdParamName) {
		this.sessionIdParamName = sessionIdParamName;
	}
	public byte getSessionIdParamType() {
		return sessionIdParamType;
	}
	public void setSessionIdParamType(byte sessionIdParamType) {
		this.sessionIdParamType = sessionIdParamType;
	}
	public AuthAccountDto getSelectedAuthAccountDto() {
		return selectedAuthAccountDto;
	}
	public void setSelectedAuthAccountDto(AuthAccountDto selectedAuthAccountDto) {
		this.selectedAuthAccountDto = selectedAuthAccountDto;
	}

}
