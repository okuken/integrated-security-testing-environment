package okuken.iste.dto;

import java.util.List;

import com.google.common.collect.Lists;

public class AuthConfigDto {

	private Integer id;

	private Integer authMessageChainId;
	private MessageChainDto authMessageChainDto;

	private List<AuthApplyConfigDto> authApplyConfigDtos = Lists.newArrayList();

	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public Integer getAuthMessageChainId() {
		return authMessageChainId;
	}
	public void setAuthMessageChainId(Integer authMessageChainId) {
		this.authMessageChainId = authMessageChainId;
	}
	public MessageChainDto getAuthMessageChainDto() {
		return authMessageChainDto;
	}
	public void setAuthMessageChainDto(MessageChainDto authMessageChainDto) {
		this.authMessageChainDto = authMessageChainDto;
		if(authMessageChainDto == null) {
			setAuthMessageChainId(null);
		} else {
			setAuthMessageChainId(authMessageChainDto.getId());
		}
	}
	public List<AuthApplyConfigDto> getAuthApplyConfigDtos() {
		return authApplyConfigDtos;
	}
	public void setAuthApplyConfigDtos(List<AuthApplyConfigDto> authApplyConfigDtos) {
		this.authApplyConfigDtos = authApplyConfigDtos;
	}

}
