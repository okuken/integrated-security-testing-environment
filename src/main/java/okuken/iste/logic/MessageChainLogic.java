package okuken.iste.logic;

import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import static org.mybatis.dynamic.sql.SqlBuilder.*;

import okuken.iste.dao.auto.MessageChainMapper;
import okuken.iste.dao.auto.MessageChainNodeDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainNodeReqpDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainNodeReqpMapper;
import okuken.iste.dao.auto.MessageChainNodeMapper;
import okuken.iste.dao.auto.MessageChainNodeRespDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainNodeRespMapper;
import okuken.iste.dao.auto.MessageChainPreVarDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainPreVarMapper;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageChainDto;
import okuken.iste.dto.MessageChainNodeDto;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.dto.MessageChainNodeRespDto;
import okuken.iste.dto.MessageChainPresetVarDto;
import okuken.iste.dto.MessageChainRepeatDto;
import okuken.iste.entity.auto.MessageChain;
import okuken.iste.entity.auto.MessageChainNode;
import okuken.iste.entity.auto.MessageChainNodeReqp;
import okuken.iste.entity.auto.MessageChainNodeResp;
import okuken.iste.entity.auto.MessageChainPreVar;
import okuken.iste.enums.EncodeType;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.ResponseParameterType;
import okuken.iste.enums.SourceType;
import okuken.iste.util.DbUtil;
import okuken.iste.util.MessageUtil;
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
	public void saveMessageChain(MessageChainDto chainDto, boolean isAuthChain) {

		if(isAuthChain) {
			chainDto.getNodes().forEach(node -> node.setBreakpoint(false));
		}

		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			var messageChainMapper = session.getMapper(MessageChainMapper.class);
			var messageChainNodeMapper = session.getMapper(MessageChainNodeMapper.class);
			var messageChainNodeReqpMapper = session.getMapper(MessageChainNodeReqpMapper.class);
			var messageChainNodeRespMapper = session.getMapper(MessageChainNodeRespMapper.class);
			var messageChainPreVarMapper = session.getMapper(MessageChainPreVarMapper.class);

			//TODO: auto convert
			var chain = new MessageChain();
			chain.setId(chainDto.getId());
			chain.setFkMessageId(chainDto.getMessageId());
			chain.setPrcDate(now);
			boolean isUpdate = chainDto.getId() != null;
			if(isUpdate) {
				messageChainMapper.updateByPrimaryKey(chain);
			} else {
				messageChainMapper.insert(chain);
				chainDto.setId(chain.getId());
			}

			if(isUpdate) {
				// DELETE
				messageChainNodeMapper.select(c -> c.where(MessageChainNodeDynamicSqlSupport.fkMessageChainId, isEqualTo(chain.getId())))
					.forEach(node -> {
						messageChainNodeReqpMapper.delete(c -> c.where(MessageChainNodeReqpDynamicSqlSupport.fkMessageChainNodeId, isEqualTo(node.getId())));
						messageChainNodeRespMapper.delete(c -> c.where(MessageChainNodeRespDynamicSqlSupport.fkMessageChainNodeId, isEqualTo(node.getId())));
				});
				messageChainNodeMapper.delete(c -> c.where(MessageChainNodeDynamicSqlSupport.fkMessageChainId, isEqualTo(chain.getId())));
				messageChainPreVarMapper.delete(c -> c.where(MessageChainPreVarDynamicSqlSupport.fkMessageChainId, isEqualTo(chain.getId())));
			}

			// INSERT
			chainDto.getNodes().forEach(nodeDto -> {
				var node = new MessageChainNode();
				node.setFkMessageChainId(chainDto.getId());
				node.setFkMessageId(nodeDto.getMessageDto().getId());
				node.setMainFlg(nodeDto.isMain());
				node.setBreakpoint(nodeDto.isBreakpoint());
				node.setPrcDate(now);
				messageChainNodeMapper.insert(node);
				nodeDto.setId(node.getId());

				nodeDto.getReqps().forEach(reqpDto -> {
					var reqpEntity = new MessageChainNodeReqp();
					reqpEntity.setFkMessageChainNodeId(nodeDto.getId());
					reqpEntity.setParamType(Byte.toUnsignedInt(reqpDto.getParamType().getId()));
					reqpEntity.setParamName(reqpDto.getParamName());
					reqpEntity.setSourceType(Byte.toUnsignedInt(reqpDto.getSourceType().getId()));
					reqpEntity.setSourceName(reqpDto.getSourceName());
					reqpEntity.setEncode(Integer.toString(reqpDto.getEncode().getId()));
					reqpEntity.setPrcDate(now);
					messageChainNodeReqpMapper.insert(reqpEntity);
					reqpDto.setId(reqpEntity.getId());
				});

				nodeDto.getResps().forEach(respDto -> {
					var respEntity = new MessageChainNodeResp();
					respEntity.setFkMessageChainNodeId(nodeDto.getId());
					respEntity.setParamType(Byte.toUnsignedInt(respDto.getParamType().getId()));
					respEntity.setParamName(respDto.getParamName());
					respEntity.setVarName(respDto.getVarName());
					respEntity.setPrcDate(now);
					messageChainNodeRespMapper.insert(respEntity);
					respDto.setId(respEntity.getId());
				});
			});

			chainDto.getPresetVars().forEach(presetVarDto -> {
				var presetVarEntity = new MessageChainPreVar();
				presetVarEntity.setFkMessageChainId(chainDto.getId());
				presetVarEntity.setName(presetVarDto.getName());
				presetVarEntity.setValue(presetVarDto.getValue());
				presetVarEntity.setPrcDate(now);
				messageChainPreVarMapper.insert(presetVarEntity);
				presetVarDto.setId(presetVarEntity.getId());
			});
		});
	}

	public MessageChainDto loadMessageChain(Integer chainId) {
		//TODO: table join
		return DbUtil.withSession(session -> {
			var messageChainMapper = session.getMapper(MessageChainMapper.class);
			var messageChainNodeMapper = session.getMapper(MessageChainNodeMapper.class);
			var messageChainNodeReqpMapper = session.getMapper(MessageChainNodeReqpMapper.class);
			var messageChainNodeRespMapper = session.getMapper(MessageChainNodeRespMapper.class);
			var messageChainPreVarMapper = session.getMapper(MessageChainPreVarMapper.class);

			var chain = messageChainMapper.selectByPrimaryKey(chainId).get();
			var ret = new MessageChainDto();
			ret.setId(chain.getId());
			ret.setMessageId(chain.getFkMessageId());

			var nodes = messageChainNodeMapper.select(c -> c
					.where(MessageChainNodeDynamicSqlSupport.fkMessageChainId, isEqualTo(ret.getId()))
					.orderBy(MessageChainNodeDynamicSqlSupport.id));

			var nodeDtos = nodes.stream().map(node -> {
				var nodeDto = new MessageChainNodeDto();
				nodeDto.setId(node.getId());
				nodeDto.setMessageDto(MessageLogic.getInstance().loadMessage(node.getFkMessageId()));
				nodeDto.setMain(node.getMainFlg());
				nodeDto.setBreakpoint(node.getBreakpoint());

				nodeDto.setReqps(
					messageChainNodeReqpMapper.select(c -> c
						.where(MessageChainNodeReqpDynamicSqlSupport.fkMessageChainNodeId, isEqualTo(nodeDto.getId()))
						.orderBy(MessageChainNodeReqpDynamicSqlSupport.id))
						.stream().map(reqpEntity -> {
							var reqpDto = new MessageChainNodeReqpDto();
							reqpDto.setId(reqpEntity.getId());
							reqpDto.setParamType(RequestParameterType.getById((byte)(int)reqpEntity.getParamType()));
							reqpDto.setParamName(reqpEntity.getParamName());
							reqpDto.setSourceType(SourceType.getById((byte)(int)Optional.ofNullable(reqpEntity.getSourceType()).orElse(0)));
							reqpDto.setSourceName(reqpEntity.getSourceName());
							reqpDto.setEncode(EncodeType.getById(Integer.parseInt(Optional.ofNullable(reqpEntity.getEncode()).orElse("0"))));
							return reqpDto;
						}).collect(Collectors.toList()));

				nodeDto.setResps(
					messageChainNodeRespMapper.select(c -> c
						.where(MessageChainNodeRespDynamicSqlSupport.fkMessageChainNodeId, isEqualTo(nodeDto.getId()))
						.orderBy(MessageChainNodeRespDynamicSqlSupport.id))
						.stream().map(respEntity -> {
							var respDto = new MessageChainNodeRespDto();
							respDto.setId(respEntity.getId());
							respDto.setParamType(ResponseParameterType.getById((byte)(int)respEntity.getParamType()));
							respDto.setParamName(respEntity.getParamName());
							respDto.setVarName(respEntity.getVarName());
							return respDto;
						}).collect(Collectors.toList()));

				return nodeDto;
			}).collect(Collectors.toList());

			ret.setNodes(nodeDtos);

			ret.setPresetVars(
				messageChainPreVarMapper.select(c -> c
					.where(MessageChainPreVarDynamicSqlSupport.fkMessageChainId, isEqualTo(chain.getId()))
					.orderBy(MessageChainPreVarDynamicSqlSupport.id))
					.stream().map(entity -> {
						var dto = new MessageChainPresetVarDto();
						dto.setId(entity.getId());
						dto.setName(entity.getName());
						dto.setValue(entity.getValue());
						return dto;
					}).collect(Collectors.toList()));

			return ret;
		});
	}

	public Integer getMessageChainIdByBaseMessageId(Integer messageId) {
		return DbUtil.withSession(session -> {
			var messageChainMapper = session.getMapper(MessageChainMapper.class);

			var entity = messageChainMapper.selectOne(c -> c
					.where(MessageChainNodeDynamicSqlSupport.fkMessageId, isEqualTo(messageId)));

			if(entity.isPresent()) {
				return entity.get().getId();
			}
			return null;
		});
	}

	public MessageChainRepeatDto sendMessageChain(MessageChainDto messageChainDto, AuthAccountDto authAccountDto, BiConsumer<MessageChainRepeatDto, Integer> callback, boolean forAuth, boolean needSaveHistory, MessageChainRepeatDto breakingMessageChainRepeatDto) {
		var messageChainRepeatDto = new MessageChainRepeatDto(messageChainDto, authAccountDto);
		if(messageChainDto.getNodes().isEmpty()) {
			if(callback != null) {
				callback.accept(messageChainRepeatDto , -1);
			}
			return messageChainRepeatDto;
		}

		if(breakingMessageChainRepeatDto != null) {
			messageChainRepeatDto.applyBreakingInfo(breakingMessageChainRepeatDto);
		}

		sendMessageChainImpl(messageChainRepeatDto, callback, forAuth, needSaveHistory);
		return messageChainRepeatDto;
	}
	private void sendMessageChainImpl(MessageChainRepeatDto messageChainRepeatDto, BiConsumer<MessageChainRepeatDto, Integer> callback, boolean forAuth, boolean needSaveHistory) {
		if(messageChainRepeatDto.isForceTerminate()) {
			if(callback != null) {
				callback.accept(messageChainRepeatDto, messageChainRepeatDto.getCurrentIndex());
			}
			return;
		}

		var node = messageChainRepeatDto.getCurrentNodeDto();

		byte[] request = null;
		if(messageChainRepeatDto.isBreaking()) {
			messageChainRepeatDto.setBreaking(false);
			request = node.getRequest();
		} else if(node.isBreakpoint()) {
			messageChainRepeatDto.setBreaking(true);
			messageChainRepeatDto.setBreakingAppliedRequestForView(applyPayload(node, messageChainRepeatDto));
			if(callback != null) {
				callback.accept(messageChainRepeatDto, messageChainRepeatDto.getCurrentIndex());
			}
			return;
		} else {
			request = applyPayload(node, messageChainRepeatDto);
		}

		RepeaterLogic.getInstance().sendRequest(
				request,
				messageChainRepeatDto.getAuthAccountDto(),
				node.getMessageDto(),
				(messageRepeatDto) -> {
					messageChainRepeatDto.getMessageRepeatDtos().add(messageRepeatDto);
					updateVars(messageChainRepeatDto);

					if(callback != null) {
						callback.accept(messageChainRepeatDto, messageChainRepeatDto.getCurrentIndex());
					}

					if(messageChainRepeatDto.hasNext()) {
						messageChainRepeatDto.next();
						sendMessageChainImpl(messageChainRepeatDto, callback, forAuth, needSaveHistory);
					}
				}, forAuth, needSaveHistory && node.isMain(), true);
	}

	private byte[] applyPayload(MessageChainNodeDto node, MessageChainRepeatDto messageChainRepeatDto) {
		return MessageUtil.applyPayloads(node.getRequest(), node.getReqps(), messageChainRepeatDto.getVars(), messageChainRepeatDto.getAuthAccountDto());
	}

	private void updateVars(MessageChainRepeatDto messageChainRepeatDto) {
		var response = messageChainRepeatDto.getMessageRepeatDtos().get(messageChainRepeatDto.getCurrentIndex()).getMessage().getResponse();
		if(response == null) {
			return;
		}

		messageChainRepeatDto.getCurrentNodeDto().getResps().forEach(resp -> {
			var paramValue = MessageUtil.extractResponseParam(response, resp.getParamType(), resp.getParamName());
			if(paramValue != null) {
				messageChainRepeatDto.getVars().put(resp.getVarName(), paramValue);
			}
		});
	}

}
