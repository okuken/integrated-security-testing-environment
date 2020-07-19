package okuken.iste.logic;

import java.util.List;
import java.util.stream.Collectors;

import org.mybatis.dynamic.sql.SqlBuilder;

import okuken.iste.dao.AuthAccountDynamicSqlSupport;
import okuken.iste.dao.AuthAccountMapper;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.entity.AuthAccount;
import okuken.iste.util.BurpUtil;
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
	public void saveAuthAccount(AuthAccountDto dto) {
		try {
			String now = SqlUtil.now();
			DbUtil.withTransaction(session -> {
				AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);

				//TODO: auto convert
				AuthAccount entity = new AuthAccount();
				entity.setId(dto.getId());
				entity.setFkProjectId(ConfigLogic.getInstance().getProjectId());
				entity.setUserId(dto.getUserId());
				entity.setPassword(dto.getPassword());
				entity.setRemark(dto.getRemark());
				entity.setSessionId(dto.getSessionId());
				entity.setPrcDate(now);

				if(entity.getId() != null) {
					mapper.updateByPrimaryKey(entity);
					return;
				}

				mapper.insert(entity);
				dto.setId(entity.getId());
			});

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public List<AuthAccountDto> loadAuthAccounts() {
		try {
			List<AuthAccount> entitys =
				DbUtil.withSession(session -> {
					AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);
					return mapper.select(c -> c
							.where(AuthAccountDynamicSqlSupport.fkProjectId, SqlBuilder.isEqualTo(ConfigLogic.getInstance().getProjectId()))
							.orderBy(AuthAccountDynamicSqlSupport.id));
				});

			return entitys.stream().map(entity -> {//TODO: auto convert
				AuthAccountDto dto = new AuthAccountDto();
				dto.setId(entity.getId());
				dto.setUserId(entity.getUserId());
				dto.setPassword(entity.getPassword());
				dto.setRemark(entity.getRemark());
				dto.setSessionId(entity.getSessionId());
				return dto;
			}).collect(Collectors.toList());

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public void deleteAuthAccounts(List<AuthAccountDto> dtos) {
		try {
			DbUtil.withTransaction(session -> {
				AuthAccountMapper mapper = session.getMapper(AuthAccountMapper.class);

				dtos.forEach(dto -> { //TODO: logical delete?
					mapper.deleteByPrimaryKey(dto.getId());
				});
			});

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

}
