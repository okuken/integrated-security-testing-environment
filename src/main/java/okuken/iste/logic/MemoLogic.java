package okuken.iste.logic;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.mybatis.dynamic.sql.SqlBuilder;

import okuken.iste.dao.MemoMessageDynamicSqlSupport;
import okuken.iste.dao.MemoMessageMapper;
import okuken.iste.dao.MemoProjectDynamicSqlSupport;
import okuken.iste.dao.MemoProjectMapper;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.ProjectMemoDto;
import okuken.iste.entity.MemoMessage;
import okuken.iste.entity.MemoProject;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;

public class MemoLogic {

	private static final MemoLogic instance = new MemoLogic();
	private MemoLogic() {}
	public static MemoLogic getInstance() {
		return instance;
	}

	public void saveMessageMemo(MessageDto messageDto) {
		try {
			String now = SqlUtil.now();
			DbUtil.withTransaction(session -> {
				MemoMessageMapper mapper = session.getMapper(MemoMessageMapper.class);

				MemoMessage entity = new MemoMessage();
				entity.setFkMessageId(messageDto.getId());
				entity.setMemo(messageDto.getMemoWithoutLoad());
				entity.setPrcDate(now);
				mapper.insert(entity);
				int memoId = SqlUtil.loadGeneratedId(session);
				messageDto.setMemoId(memoId);
			});
			messageDto.setMemoChanged(false);
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public void updateMessageMemo(MessageDto messageDto) {
		try {
			String now = SqlUtil.now();
			DbUtil.withTransaction(session -> {
				MemoMessageMapper mapper = session.getMapper(MemoMessageMapper.class);

				MemoMessage entity = new MemoMessage();
				entity.setId(messageDto.getMemoId());
				entity.setMemo(messageDto.getMemo());
				entity.setPrcDate(now);
				mapper.updateByPrimaryKeySelective(entity);
			});
			messageDto.setMemoChanged(false);
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public void loadMessageMemo(MessageDto messageDto) {
		try {
			Optional<MemoMessage> entity =
				DbUtil.withSession(session -> {
					MemoMessageMapper mapper = session.getMapper(MemoMessageMapper.class);
					return mapper.selectOne(c -> c.where(MemoMessageDynamicSqlSupport.fkMessageId, SqlBuilder.isEqualTo(messageDto.getId())));
				});

			if(entity.isPresent()) {
				messageDto.setMemo(entity.get().getMemo());
				messageDto.setMemoId(entity.get().getId());
			} else {
				messageDto.setMemo("");
				messageDto.setMemoId(null);
			}

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}


	/**
	 * insert or update.
	 */
	public void saveProjectMemo(ProjectMemoDto memoDto) {
		try {
			String now = SqlUtil.now();
			Integer projectId = ConfigLogic.getInstance().getProjectId();
			DbUtil.withTransaction(session -> {
				MemoProjectMapper mapper = session.getMapper(MemoProjectMapper.class);

				MemoProject entity = new MemoProject();
				entity.setId(memoDto.getId());
				entity.setFkProjectId(projectId);
				entity.setMemo(memoDto.getMemo());
				entity.setPrcDate(now);

				if(entity.getId() != null) {
					mapper.updateByPrimaryKey(entity);
					return;
				}

				mapper.insert(entity);
				memoDto.setId(entity.getId());

			});
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public List<ProjectMemoDto> loadProjectMemos() {
		try {
			List<MemoProject> entitys =
				DbUtil.withSession(session -> {
					MemoProjectMapper mapper = session.getMapper(MemoProjectMapper.class);
					return mapper.select(c -> c
							.where(MemoProjectDynamicSqlSupport.fkProjectId, SqlBuilder.isEqualTo(ConfigLogic.getInstance().getProjectId()))
							.orderBy(MemoProjectDynamicSqlSupport.id));
				});

			return entitys.stream().map(entity -> {
				var dto = new ProjectMemoDto();
				dto.setId(entity.getId());
				dto.setMemo(entity.getMemo());
				return dto;
			}).collect(Collectors.toList());

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

}
