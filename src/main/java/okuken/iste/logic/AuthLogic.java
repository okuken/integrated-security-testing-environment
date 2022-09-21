package okuken.iste.logic;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.mybatis.dynamic.sql.SqlBuilder.*;

import okuken.iste.consts.Captions;
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
import okuken.iste.dto.MessageChainRepeatDto;
import okuken.iste.entity.auto.AuthAccount;
import okuken.iste.entity.auto.AuthApplyConfig;
import okuken.iste.entity.auto.AuthConfig;
import okuken.iste.enums.EncodeType;
import okuken.iste.enums.OrderType;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SourceType;
import okuken.iste.util.DbUtil;
import okuken.iste.util.ReflectionUtil;
import okuken.iste.util.SqlUtil;
import okuken.iste.view.chain.ChainDefPanel;

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

			AuthAccount entity = new AuthAccount();
			entity.setId(dto.getId());
			entity.setFkProjectId(ConfigLogic.getInstance().getProjectId());
			ReflectionUtil.setNumberedFields(entity, AuthAccountDto.FIELD_SETTER_FORMAT, AuthAccountDto.FIELD_START_NUM, AuthAccountDto.FIELD_END_NUM, String.class, dto, AuthAccountDto.FIELD_GETTER_FORMAT);
			entity.setRemark(dto.getRemark());
			ReflectionUtil.setNumberedFields(entity, AuthAccountDto.SESSIONID_SETTER_FORMAT, AuthAccountDto.SESSIONID_START_NUM, AuthAccountDto.SESSIONID_END_NUM, String.class, dto.getSessionIds());
			entity.setPrcDate(now);

			if(entity.getId() != null) {
				if(keepOldSessionId) {
					ReflectionUtil.setNumberedFields(entity, AuthAccountDto.SESSIONID_SETTER_FORMAT, AuthAccountDto.SESSIONID_START_NUM, AuthAccountDto.SESSIONID_END_NUM, String.class,
							mapper.selectByPrimaryKey(entity.getId()).get(), AuthAccountDto.SESSIONID_GETTER_FORMAT);
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
					.set(AuthAccountDynamicSqlSupport.sessionId01).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId02).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId03).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId04).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId05).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId06).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId07).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId08).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId09).equalToNull()
					.set(AuthAccountDynamicSqlSupport.sessionId10).equalToNull()
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

		var authAccountDtos = entitys.stream().map(entity -> {
			AuthAccountDto dto = new AuthAccountDto();
			dto.setId(entity.getId());
			ReflectionUtil.setNumberedFields(dto, AuthAccountDto.FIELD_SETTER_FORMAT, AuthAccountDto.FIELD_START_NUM, AuthAccountDto.FIELD_END_NUM, String.class, entity, AuthAccountDto.FIELD_GETTER_FORMAT);
			dto.setRemark(entity.getRemark());
			dto.setSessionIds(ReflectionUtil.getNumberedFieldsAsList(entity, AuthAccountDto.SESSIONID_GETTER_FORMAT, AuthAccountDto.SESSIONID_START_NUM, AuthAccountDto.SESSIONID_END_NUM));
			return dto;
		}).collect(Collectors.toList());

		return OrderLogic.getInstance().sortByOrder(authAccountDtos, OrderType.AUTH_ACCOUNT);
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
		MessageChainLogic.getInstance().saveMessageChain(messageChainDto, true);

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

			var authApplyConfigDtos = authApplyConfigMapper.select(c -> c
					.where(AuthApplyConfigDynamicSqlSupport.fkAuthConfigId, isEqualTo(dto.getId()))
					.orderBy(AuthApplyConfigDynamicSqlSupport.id))
					.stream().map(applyEntity -> {
						var applyDto = new AuthApplyConfigDto();
						applyDto.setId(applyEntity.getId());
						applyDto.setAuthConfigId(dto.getId());
						applyDto.setParamType(RequestParameterType.getById((byte)(int)applyEntity.getParamType()));
						applyDto.setParamName(applyEntity.getParamName());
						applyDto.setSourceType(SourceType.getById((byte)(int)applyEntity.getSourceType()));
						applyDto.setSourceName(applyEntity.getSourceName());
						applyDto.setEncode(EncodeType.getById(Integer.parseInt(Optional.ofNullable(applyEntity.getEncode()).orElse("0"))));
						return applyDto;
					}).collect(Collectors.toList());
			dto.setAuthApplyConfigDtos(OrderLogic.getInstance().sortByOrder(authApplyConfigDtos, OrderType.AUTH_APPLY_CONFIG));

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
			entity.setSourceType((int)dto.getSourceType().getId());
			entity.setSourceName(dto.getSourceName());
			entity.setEncode(Integer.toString(dto.getEncode().getId()));
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
		sendLoginRequestAndSetSessionId(authAccountDto, ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainDto(), callback);
	}
	private void sendLoginRequestAndSetSessionId(AuthAccountDto authAccountDto, MessageChainDto authMessageChainDto, Consumer<AuthAccountDto> callback) {

		if(authMessageChainDto.getNodes().stream().anyMatch(node -> node.isBreakpoint())) {
			ChainDefPanel.openAutoStartChainModalFrame(ConfigLogic.getInstance().getAuthConfig().getAuthMessageChainId(), Captions.AUTH_CONFIG_CHAIN, authAccountDto);
			if(callback != null) {
				callback.accept(authAccountDto);
			}
			return;
		}

		MessageChainLogic.getInstance().sendMessageChain(authMessageChainDto, authAccountDto, (messageChainRepeatDto, index) -> {
			if(index + 1 < authMessageChainDto.getNodes().size()) {
				return;
			}

			updateSessionIds(authAccountDto, messageChainRepeatDto);

			if(callback != null) {
				callback.accept(authAccountDto);
			}

		}, true, false, null);
	}

	public void updateSessionIds(AuthAccountDto authAccountDto, MessageChainRepeatDto messageChainRepeatDto) {
		authAccountDto.setSessionIds(
			ConfigLogic.getInstance().getAuthConfig().getAuthApplyConfigDtos().stream().map(authApplyConfigDto -> {
				switch (authApplyConfigDto.getSourceType()) {
				case VAR:
					if(!messageChainRepeatDto.getVars().containsKey(authApplyConfigDto.getSourceName())) {
						return null;
					}
					return messageChainRepeatDto.getVars().get(authApplyConfigDto.getSourceName());
				case AUTH_ACCOUNT_TABLE:
					return authAccountDto.getField(authApplyConfigDto.getSourceName());
				default:
					throw new IllegalArgumentException(authApplyConfigDto.getSourceType().name());
				}
			}).collect(Collectors.toList()));

		saveAuthAccount(authAccountDto, false);
	}

}
