package okuken.iste.logic;

import java.util.stream.Collectors;

import org.mybatis.dynamic.sql.SqlBuilder;

import okuken.iste.dao.auto.MessageChainMapper;
import okuken.iste.dao.auto.MessageChainNodeDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainNodeInDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainNodeInMapper;
import okuken.iste.dao.auto.MessageChainNodeMapper;
import okuken.iste.dao.auto.MessageChainNodeOutDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainNodeOutMapper;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainNodeInDto;
import okuken.iste.dto.MessageChainNodeOutDto;
import okuken.iste.entity.auto.MessageChain;
import okuken.iste.entity.auto.MessageChainNode;
import okuken.iste.entity.auto.MessageChainNodeIn;
import okuken.iste.entity.auto.MessageChainNodeOut;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.DbUtil;
import okuken.iste.util.SqlUtil;

public class MessageChainLogic {

	private static final MessageChainLogic instance = new MessageChainLogic();
	private MessageChainLogic() {}
	public static MessageChainLogic getInstance() {
		return instance;
	}

	/**
	 * insert or update.
	 */
	public void saveMessageChain(MessageChainDto chainDto) {
		try {
			String now = SqlUtil.now();
			DbUtil.withTransaction(session -> {
				var messageChainMapper = session.getMapper(MessageChainMapper.class);
				var messageChainNodeMapper = session.getMapper(MessageChainNodeMapper.class);
				var messageChainNodeInMapper = session.getMapper(MessageChainNodeInMapper.class);
				var messageChainNodeOutMapper = session.getMapper(MessageChainNodeOutMapper.class);

				//TODO: auto convert
				var chain = new MessageChain();
				chain.setId(chainDto.getId());
				chain.setFkMessageId(chainDto.getMessageId());
				chain.setPrcDate(now);
				if(chainDto.getId() != null) {
					messageChainMapper.updateByPrimaryKey(chain);
				} else {
					messageChainMapper.insert(chain);
					chainDto.setId(chain.getId());
				}

				//TODO: ****(DELETE-INSERT)****

				chainDto.getNodes().forEach(nodeDto -> {
					var node = new MessageChainNode();
					node.setId(nodeDto.getId());
					node.setFkMessageChainId(chainDto.getId());
					node.setFkMessageId(nodeDto.getMessageDto().getId());
					node.setPrcDate(now);
					if(nodeDto.getId() != null) {
						messageChainNodeMapper.updateByPrimaryKey(node);
					} else {
						messageChainNodeMapper.insert(node);
						nodeDto.setId(node.getId());
					}

					nodeDto.getIns().forEach(inDto -> {
						var inEntity = new MessageChainNodeIn();
						inEntity.setId(inDto.getId());
						inEntity.setFkMessageChainNodeId(nodeDto.getId());
						inEntity.setParamType(Byte.toUnsignedInt(inDto.getParamType()));
						inEntity.setParamName(inDto.getParamName());
						inEntity.setVarName(inDto.getVarName());
						inEntity.setPrcDate(now);
						if(inDto.getId() != null) {
							messageChainNodeInMapper.updateByPrimaryKey(inEntity);
						} else {
							messageChainNodeInMapper.insert(inEntity);
							inDto.setId(inEntity.getId());
						}
					});

					nodeDto.getOuts().forEach(outDto -> {
						var outEntity = new MessageChainNodeOut();
						outEntity.setId(outDto.getId());
						outEntity.setFkMessageChainNodeId(nodeDto.getId());
						outEntity.setParamType(Byte.toUnsignedInt(outDto.getParamType()));
						outEntity.setParamName(outDto.getParamName());
						outEntity.setRegex(outDto.getRegex());
						outEntity.setVarName(outDto.getVarName());
						outEntity.setPrcDate(now);
						if(outDto.getId() != null) {
							messageChainNodeOutMapper.updateByPrimaryKey(outEntity);
						} else {
							messageChainNodeOutMapper.insert(outEntity);
							outDto.setId(outEntity.getId());
						}
					});
				});
			});

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

	public MessageChainDto loadMessageChain(Integer chainId) {
		try {
			//TODO: table join
			return DbUtil.withSession(session -> {
				var messageChainMapper = session.getMapper(MessageChainMapper.class);
				var messageChainNodeMapper = session.getMapper(MessageChainNodeMapper.class);
				var messageChainNodeInMapper = session.getMapper(MessageChainNodeInMapper.class);
				var messageChainNodeOutMapper = session.getMapper(MessageChainNodeOutMapper.class);

				var chain = messageChainMapper.selectByPrimaryKey(chainId).get();
				var ret = new MessageChainDto();
				ret.setId(chain.getId());
				ret.setMessageId(chain.getFkMessageId());

				var nodes = messageChainNodeMapper.select(c -> c
						.where(MessageChainNodeDynamicSqlSupport.fkMessageChainId, SqlBuilder.isEqualTo(ret.getId()))
						.orderBy(MessageChainNodeDynamicSqlSupport.id));

				var nodeDtos = nodes.stream().map(node -> {
					var nodeDto = new MessageChainNodeDto();
					nodeDto.setId(node.getId());
					nodeDto.setMessageDto(MessageLogic.getInstance().loadMessage(node.getFkMessageId()));

					nodeDto.setIns(
						messageChainNodeInMapper.select(c -> c
							.where(MessageChainNodeInDynamicSqlSupport.fkMessageChainNodeId, SqlBuilder.isEqualTo(nodeDto.getId()))
							.orderBy(MessageChainNodeInDynamicSqlSupport.id))
							.stream().map(inEntity -> {
								var inDto = new MessageChainNodeInDto();
								inDto.setId(inEntity.getId());
								inDto.setParamType((byte)(int)inEntity.getParamType());
								inDto.setParamName(inEntity.getParamName());
								inDto.setVarName(inEntity.getVarName());
								return inDto;
							}).collect(Collectors.toList()));

					nodeDto.setOuts(
						messageChainNodeOutMapper.select(c -> c
							.where(MessageChainNodeOutDynamicSqlSupport.fkMessageChainNodeId, SqlBuilder.isEqualTo(nodeDto.getId()))
							.orderBy(MessageChainNodeOutDynamicSqlSupport.id))
							.stream().map(outEntity -> {
								var outDto = new MessageChainNodeOutDto();
								outDto.setId(outEntity.getId());
								outDto.setParamType((byte)(int)outEntity.getParamType());
								outDto.setParamName(outEntity.getParamName());
								outDto.setRegex(outEntity.getRegex());
								outDto.setVarName(outEntity.getVarName());
								return outDto;
							}).collect(Collectors.toList()));

					return nodeDto;
				}).collect(Collectors.toList());

				ret.setNodes(nodeDtos);
				return ret;
			});

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			throw e;
		}
	}

}
