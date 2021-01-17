package okuken.iste.logic;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.mybatis.dynamic.sql.SqlBuilder.*;

import okuken.iste.dao.auto.AuthAccountDynamicSqlSupport;
import okuken.iste.dao.auto.AuthAccountMapper;
import okuken.iste.dao.auto.AuthApplyConfigDynamicSqlSupport;
import okuken.iste.dao.auto.AuthApplyConfigMapper;
import okuken.iste.dao.auto.AuthConfigDynamicSqlSupport;
import okuken.iste.dao.auto.AuthConfigMapper;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.AuthApplyConfigDto;
import okuken.iste.dto.AuthConfigDto;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.entity.auto.AuthAccount;
import okuken.iste.entity.auto.AuthApplyConfig;
import okuken.iste.entity.auto.AuthConfig;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;

public class AuthLogic {

	private static final AuthLogic instance = new AuthLogic();
	private AuthLogic() {}
	public static AuthLogic getInstance() {
		return instance;
	}

	/**
	 * insert or update.
	 */
	public void saveAuthAccount(AuthAccountDto dto, boolean keepOldSessionId) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);

			//TODO: auto convert
			AuthAccount entity = new AuthAccount();
			entity.setId(dto.getId());
			entity.setFkProjectId(ConfigLogic.getInstance().getProjectId());
			entity.setField01(dto.getField01());
			entity.setField02(dto.getField02());
			entity.setField03(dto.getField03());
			entity.setField04(dto.getField04());
			entity.setField05(dto.getField05());
			entity.setRemark(dto.getRemark());
			entity.setSessionId(dto.getSessionId());
			entity.setPrcDate(now);

			if(entity.getId() != null) {
				if(keepOldSessionId) {
					entity.setSessionId(mapper.selectByPrimaryKey(entity.getId()).get().getSessionId());
				}

				mapper.updateByPrimaryKey(entity);
				return;
			}

			mapper.insert(entity);
			dto.setId(entity.getId());
		});
	}

	public void clearAuthAccountsSession() {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);

			mapper.update(c -> c
					.set(AuthAccountDynamicSqlSupport.sessionId).equalToNull()
					.set(AuthAccountDynamicSqlSupport.prcDate).equalTo(now)
					.where(AuthAccountDynamicSqlSupport.fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId())));
		});
	}

	public List<AuthAccountDto> loadAuthAccounts() {
		List<AuthAccount> entitys =
			DbUtil.withSession(session -> {
				AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);
				return mapper.select(c -> c
						.where(AuthAccountDynamicSqlSupport.fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId()))
						.orderBy(AuthAccountDynamicSqlSupport.id));
			});

		return entitys.stream().map(entity -> {//TODO: auto convert
			AuthAccountDto dto = new AuthAccountDto();
			dto.setId(entity.getId());
			dto.setField01(entity.getField01());
			dto.setField02(entity.getField02());
			dto.setField03(entity.getField03());
			dto.setField04(entity.getField04());
			dto.setField05(entity.getField05());
			dto.setRemark(entity.getRemark());
			dto.setSessionId(entity.getSessionId());
			return dto;
		}).collect(Collectors.toList());
	}

	public void deleteAuthAccounts(List<AuthAccountDto> dtos) {
		DbUtil.withTransaction(session -> {
			AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);

			dtos.forEach(dto -> { //TODO: logical delete?
				mapper.deleteByPrimaryKey(dto.getId());
			});
		});
	}

	public AuthConfigDto initAuthConfig() {
		var messageChainDto = new MessageChainDto();
		MessageChainLogic.getInstance().saveMessageChain(messageChainDto);

		var authConfigDto = new AuthConfigDto();
		authConfigDto.setAuthMessageChainDto(messageChainDto);
		saveAuthConfig(authConfigDto);

		return authConfigDto;
	}

	/**
	 * insert or update.
	 */
	public void saveAuthConfig(AuthConfigDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			var mapper = session.getMapper(AuthConfigMapper.class);

			//TODO: auto convert
			var entity = new AuthConfig();
			entity.setId(dto.getId());
			entity.setFkProjectId(ConfigLogic.getInstance().getProjectId());
			entity.setFkMessageChainId(dto.getAuthMessageChainId());
			entity.setPrcDate(now);

			if(entity.getId() != null) {
				mapper.updateByPrimaryKey(entity);
				return;
			}

			mapper.insert(entity);
			dto.setId(entity.getId());
		});
	}

	public AuthConfigDto loadAuthConfig() {
		var ret = DbUtil.withSession(session -> {
			var authConfigMapper = session.getMapper(AuthConfigMapper.class);
			var authApplyConfigMapper = session.getMapper(AuthApplyConfigMapper.class);

			var entityOptional = authConfigMapper.selectOne(c -> c.where(AuthConfigDynamicSqlSupport.fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId())));
			if(entityOptional.isEmpty()) {
				return null;
			}
			var entity = entityOptional.get();

			var dto = new AuthConfigDto();
			dto.setId(entity.getId());
			dto.setAuthMessageChainId(entity.getFkMessageChainId());

			dto.setAuthApplyConfigDtos(
				authApplyConfigMapper.select(c -> c
					.where(AuthApplyConfigDynamicSqlSupport.fkAuthConfigId, isEqualTo(dto.getId()))
					.orderBy(AuthApplyConfigDynamicSqlSupport.id))
					.stream().map(applyEntity -> {
						var applyDto = new AuthApplyConfigDto();
						applyDto.setId(applyEntity.getId());
						applyDto.setAuthConfigId(dto.getId());
						applyDto.setParamType(RequestParameterType.getById((byte)(int)applyEntity.getParamType()));
						applyDto.setParamName(applyEntity.getParamName());
						applyDto.setVarName(applyEntity.getVarName());
						return applyDto;
					}).collect(Collectors.toList()));

			return dto;
		});

		if(ret == null) {
			return ret;
		}

		var messageChainDto = MessageChainLogic.getInstance().loadMessageChain(ret.getAuthMessageChainId());
		ret.setAuthMessageChainDto(messageChainDto);

		return ret;
	}

	/**
	 * insert or update.
	 */
	public void saveAuthApplyConfig(AuthApplyConfigDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			AuthApplyConfigMapper mapper = session.getMapper(AuthApplyConfigMapper.class);

			//TODO: auto convert
			AuthApplyConfig entity = new AuthApplyConfig();
			entity.setId(dto.getId());
			entity.setFkAuthConfigId(dto.getAuthConfigId());
			entity.setParamType((int)dto.getParamType().getId());
			entity.setParamName(dto.getParamName());
			entity.setVarName(dto.getVarName());
			entity.setPrcDate(now);

			if(entity.getId() != null) {
				mapper.updateByPrimaryKey(entity);
				return;
			}

			mapper.insert(entity);
			dto.setId(entity.getId());
		});
	}

	public void deleteAuthApplyConfigs(List<AuthApplyConfigDto> dtos) {
		DbUtil.withTransaction(session -> {
			AuthApplyConfigMapper mapper = session.getMapper(AuthApplyConfigMapper.class);

			dtos.forEach(dto -> {
				mapper.deleteByPrimaryKey(dto.getId());
			});
		});
	}

	public void sendLoginRequestAndSetSessionId(AuthAccountDto authAccountDto, Consumer<AuthAccountDto> callback) {
		sendLoginRequestAndSetSessionId(authAccountDto, ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainDto(), callback, false);
	}
	private void sendLoginRequestAndSetSessionId(AuthAccountDto authAccountDto, MessageChainDto authMessageChainDto, Consumer<AuthAccountDto> callback, boolean isTest) {
		MessageChainLogic.getInstance().sendMessageChain(authMessageChainDto, authAccountDto, (messageChainRepeatDto, index) -> {
			if(index + 1 < authMessageChainDto.getNodes().size()) {
				return;
			}

			//TODO: support multiple authApplyConfigs case
			var varName = ConfigLogic.getInstance().getAuthConfig().getAuthApplyConfigDtos().get(0).getVarName();
			if(messageChainRepeatDto.getVars().containsKey(varName)) {
				authAccountDto.setSessionId(messageChainRepeatDto.getVars().get(varName));

				if(!isTest) {
					saveAuthAccount(authAccountDto, false);
				}
			}

			if(callback != null) {
				callback.accept(authAccountDto);
			}

		}, true, false);
	}

}
