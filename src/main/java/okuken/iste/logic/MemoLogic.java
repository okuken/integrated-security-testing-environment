package okuken.iste.logic;

import java.util.Optional;

import org.mybatis.dynamic.sql.SqlBuilder;

import okuken.iste.dao.MemoMessageDynamicSqlSupport;
import okuken.iste.dao.MemoMessageMapper;
import okuken.iste.dto.MessageDto;
import okuken.iste.entity.MemoMessage;
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

				if (mapper.selectByPrimaryKey(messageDto.getMemoId()).get().getMemo().equals(messageDto.getMemo())) { //update only if memo is changed
					messageDto.setMemoChanged(false);
					return;
				}

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

}
