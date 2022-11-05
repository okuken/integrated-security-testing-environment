package okuken.iste.logic;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.mybatis.dynamic.sql.BasicColumn;
import org.mybatis.dynamic.sql.SqlColumn;
import org.mybatis.dynamic.sql.render.RenderingStrategies;
import org.mybatis.dynamic.sql.select.QueryExpressionDSL.JoinSpecificationFinisher;
import org.mybatis.dynamic.sql.select.SelectModel;
import org.mybatis.dynamic.sql.select.render.SelectStatementProvider;

import static org.mybatis.dynamic.sql.SqlBuilder.*;

import com.google.common.collect.Lists;

import okuken.iste.dao.auto.MessageChainDynamicSqlSupport;
import okuken.iste.dao.auto.MessageChainMapper;
import okuken.iste.dao.auto.MessageDynamicSqlSupport;
import okuken.iste.client.BurpApiClient;
import okuken.iste.dao.MessageMapper;
import okuken.iste.dao.auto.MessageOrdDynamicSqlSupport;
import okuken.iste.dao.auto.MessageOrdMapper;
import okuken.iste.dao.auto.MessageParamMapper;
import okuken.iste.dao.auto.MessageRawDynamicSqlSupport;
import okuken.iste.dao.auto.MessageRawMapper;
import okuken.iste.dao.auto.MessageRepeatMasterDynamicSqlSupport;
import okuken.iste.dao.auto.MessageRepeatMasterMapper;
import okuken.iste.dto.HttpRequestParameterDto;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpServiceDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRequestParamDto;
import okuken.iste.entity.Message;
import okuken.iste.entity.auto.MessageOrd;
import okuken.iste.entity.auto.MessageParam;
import okuken.iste.entity.auto.MessageRaw;
import okuken.iste.entity.auto.MessageRepeatMaster;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.SecurityTestingProgress;
import okuken.iste.util.DbUtil;
import okuken.iste.util.MessageUtil;
import okuken.iste.util.SqlUtil;

public class MessageLogic {

	private static final MessageLogic instance = new MessageLogic();
	private MessageLogic() {}
	public static MessageLogic getInstance() {
		return instance;
	}

	public MessageDto convertHttpRequestResponseToDto(HttpRequestResponseDto httpRequestResponse) {
		MessageDto dto = new MessageDto();
		dto.setMessage(httpRequestResponse);
		dto.setRequestInfo(BurpApiClient.i().analyzeRequest(httpRequestResponse));

		dto.setName(convertCommentToName(httpRequestResponse.getComment()));
		dto.setProgress(SecurityTestingProgress.NOT_YET);
		dto.setMethod(dto.getRequestInfo().getMethod());
		dto.setUrl(dto.getRequestInfo().getUrl());
		dto.setParams((int)dto.getRequestInfo().getParameters().stream()
				.filter(param -> param.getType() != RequestParameterType.COOKIE.getBurpId()).count());

		dto.setMessageParamList(dto.getRequestInfo().getParameters().stream()
				.map(parameter -> convertParameterToDto(parameter)).collect(Collectors.toList()));

		if(httpRequestResponse.getResponse() != null) {
			dto.setResponseInfo(BurpApiClient.i().analyzeResponse(httpRequestResponse.getResponse()));
			dto.setStatus(dto.getResponseInfo().getStatusCode());
			dto.setLength(dto.getMessage().getResponse().length);
			dto.setMimeType(dto.getResponseInfo().getStatedMimeType());
			dto.setCookies(dto.getResponseInfo().getCookies().stream()
					.map(cookie -> String.format("%s=%s", cookie.getName(), cookie.getValue()))
					.collect(Collectors.joining("; ")));

			dto.setMessageCookieList(dto.getResponseInfo().getCookies().stream()
					.map(MessageUtil::convertCookieToDto).collect(Collectors.toList()));
		}

		dto.setMemo(Optional.ofNullable(ConfigLogic.getInstance().getUserOptions().getMessageMemoTemplate()).orElse(""));

		return dto;
	}

	private String convertCommentToName(String comment) {
		if(comment == null) {
			return null;
		}

		return Arrays.asList(comment.split("\t")).stream() //consider paste from spread sheet
				.map(str -> str.stripTrailing())
				.collect(Collectors.joining(". "));
	}

	private HttpRequestResponseDto convertEntityToDto(MessageRaw messageRaw) {
		return new HttpRequestResponseDto(
				messageRaw.getRequest(),
				messageRaw.getResponse(),
				new HttpServiceDto(messageRaw.getHost(), messageRaw.getPort(), messageRaw.getProtocol()));
	}

	public MessageRequestParamDto convertParameterToDto(HttpRequestParameterDto parameter) {
		MessageRequestParamDto dto = new MessageRequestParamDto();
		dto.setType(RequestParameterType.getByBurpId(parameter.getType()));
		dto.setName(parameter.getName());
		dto.setValue(parameter.getValue());
		return dto;
	}

	private void copyEditableFieldValuesToEntity(MessageDto dto, Message message) {
		message.setName(dto.getName());
		message.setRemark(dto.getRemark());
		message.setProgress(dto.getProgress().getId());
		message.setProgressMemo(dto.getProgressMemo());

		message.setAuthMatrix(dto.getAuthMatrix());
		message.setPriority(dto.getPriority());
		message.setProgressExt01(dto.getProgressTechnical());
		message.setProgressExt02(dto.getProgressLogical());
		message.setProgressExt03(dto.getProgressAuthentication());
		message.setProgressExt04(dto.getProgressAuthorizationFeature());
		message.setProgressExt05(dto.getProgressAuthorizationResource());
		message.setProgressExt06(dto.getProgressCsrf());
	}

	public void saveMessages(List<MessageDto> dtos) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);
			MessageParamMapper messageParamMapper = session.getMapper(MessageParamMapper.class);

			for(MessageDto dto: dtos) {
				MessageRaw messageRaw = new MessageRaw();
				messageRaw.setHost(dto.getMessage().getHttpService().getHost());
				messageRaw.setPort(dto.getMessage().getHttpService().getPort());
				messageRaw.setProtocol(dto.getMessage().getHttpService().getProtocol());
				messageRaw.setRequest(dto.getMessage().getRequest());
				messageRaw.setResponse(dto.getMessage().getResponse());
				messageRaw.setPrcDate(now);
				messageRawMapper.insert(messageRaw); //TODO: generated id is not returned...
				int messageRawId = SqlUtil.loadGeneratedId(session);

				//TODO: auto convert
				Message message = new Message();
				message.setFkProjectId(ConfigLogic.getInstance().getProjectId());
				message.setFkMessageRawId(messageRawId);
				copyEditableFieldValuesToEntity(dto, message);
				message.setUrl(dto.getUrl().toExternalForm());
				message.setMethod(dto.getMethod());
				message.setParams(dto.getParams());
				message.setStatus(dto.getStatus());
				message.setLength(dto.getLength());
				message.setMimeType(dto.getMimeType());
				message.setCookies(dto.getCookies());
				message.setPrcDate(now);
				messageMapper.insert(message); //TODO: generated id is not returned...
				int messageId = SqlUtil.loadGeneratedId(session);
				dto.setId(messageId);

				for(MessageRequestParamDto paramDto: dto.getMessageParamList()) {
					//TODO: auto convert
					MessageParam messageParam = new MessageParam();
					messageParam.setFkMessageId(messageId);
					messageParam.setType(Byte.toUnsignedInt(paramDto.getType().getId()));
					messageParam.setName(paramDto.getName());
					messageParam.setValue(paramDto.getValue());
					messageParam.setPrcDate(now);
					messageParamMapper.insert(messageParam);
				}
			}
		});
	}

	/**
	 * It only updates editable fields: name.
	 * @param dto MessageDto. id is required.
	 */
	public void updateMessage(MessageDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);

			Message message = new Message();
			message.setFkProjectId(ConfigLogic.getInstance().getProjectId());
			message.setId(dto.getId());
			copyEditableFieldValuesToEntity(dto, message);
			message.setPrcDate(now);
			messageMapper.updateByPrimaryKeySelective(message);
		});
	}

	/**
	 * Logical delete.
	 */
	public void deleteMessage(MessageDto dto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageMapper messageMapper = session.getMapper(MessageMapper.class);

			Message message = new Message();
			message.setId(dto.getId());
			message.setDeleteFlg(true);
			message.setPrcDate(now);
			messageMapper.updateByPrimaryKeySelective(message);
		});
	}

	public MessageDto loadMessage(Integer id) {
		Message message = 
			DbUtil.withSession(session -> {
				@SuppressWarnings("unchecked")
				SelectStatementProvider selectStatement = ((SelectModel)createBaseSelectStatement()
						.where(MessageDynamicSqlSupport.id, isEqualTo(id))
						.build())
						.render(RenderingStrategies.MYBATIS3);

				return session.getMapper(MessageMapper.class).selectOneJoin(selectStatement);
			});

		return convertMessageEntityToDto(message);
	}

	public List<MessageDto> loadMessages() {
		List<Message> messages = 
			DbUtil.withSession(session -> {
				@SuppressWarnings("unchecked")
				SelectStatementProvider selectStatement = ((SelectModel)createBaseSelectStatement()
						.where(MessageDynamicSqlSupport.fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId()),
							and(MessageDynamicSqlSupport.deleteFlg, isFalse()))
						.build())
						.render(RenderingStrategies.MYBATIS3);

				return session.getMapper(MessageMapper.class).selectManyJoin(selectStatement);
			});

		return messages.stream().map(message -> convertMessageEntityToDto(message)).collect(Collectors.toList());
	}

	@SuppressWarnings("rawtypes")
	private JoinSpecificationFinisher createBaseSelectStatement() {
		return select(ArrayUtils.addAll(
				Arrays.stream(MessageMapper.selectList).map(c->c.as(((SqlColumn<?>)c).name())).collect(Collectors.toList()).toArray(new BasicColumn[0]),
				Arrays.stream(MessageChainMapper.selectList).map(c->c.as("mc_" + ((SqlColumn<?>)c).name())).collect(Collectors.toList()).toArray(new BasicColumn[0])))
			.from(MessageDynamicSqlSupport.message)
			.leftJoin(MessageChainDynamicSqlSupport.messageChain)
				.on(MessageDynamicSqlSupport.message.id, equalTo(MessageChainDynamicSqlSupport.messageChain.fkMessageId));
	}

	//TODO: converter
	private MessageDto convertMessageEntityToDto(Message message) {
		MessageDto dto = new MessageDto();
		dto.setId(message.getId());
		dto.setName(message.getName());
		dto.setRemark(message.getRemark());
		dto.setProgress(SecurityTestingProgress.getById(message.getProgress()));
		dto.setProgressMemo(message.getProgressMemo());

		dto.setAuthMatrix(message.getAuthMatrix());
		dto.setPriority(message.getPriority());
		dto.setProgressTechnical(message.getProgressExt01());
		dto.setProgressLogical(message.getProgressExt02());
		dto.setProgressAuthentication(message.getProgressExt03());
		dto.setProgressAuthorizationFeature(message.getProgressExt04());
		dto.setProgressAuthorizationResource(message.getProgressExt05());
		dto.setProgressCsrf(message.getProgressExt06());

		try {
			dto.setUrl(new URL(message.getUrl()));
		} catch (MalformedURLException e) {
			throw new RuntimeException(e);
		}
		dto.setMethod(message.getMethod());
		dto.setParams(message.getParams());
		dto.setStatus(message.getStatus());
		dto.setLength(message.getLength());
		dto.setMimeType(message.getMimeType());
		dto.setCookies(message.getCookies());
		dto.setMessageRawId(message.getFkMessageRawId());

		dto.setDeleteFlg(message.isDeleteFlg());

		dto.setMessageChainIds(message.getMessageChains().stream().map(chain -> chain.getId()).collect(Collectors.toList()));

		return dto;
	}

	public List<Integer> loadMessageOrder() {
		return DbUtil.withSession(session -> {
			MessageOrdMapper messageOrdMapper = session.getMapper(MessageOrdMapper.class);
			Optional<MessageOrd> messageOrd = messageOrdMapper
					.selectOne(c -> c.where(MessageOrdDynamicSqlSupport.fkProjectId, isEqualTo(ConfigLogic.getInstance().getProjectId())));

			if(messageOrd.isEmpty()) {
				return Lists.newArrayList();
			}

			var ord = messageOrd.get().getOrd();
			if(StringUtils.isBlank(ord)) {
				return Lists.newArrayList();
			}

			return Arrays.stream(ord.split(","))
					.map(Integer::valueOf)
					.collect(Collectors.toList());
		});
	}

	public void saveMessageOrder(List<MessageDto> dtos) {
		String order = dtos.stream().map(dto -> dto.getId().toString()).collect(Collectors.joining(","));
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageOrdMapper messageOrdMapper = session.getMapper(MessageOrdMapper.class);

			Optional<MessageOrd> messageOrd = messageOrdMapper
					.selectOne(c -> c.where(MessageOrdDynamicSqlSupport.fkProjectId,
							isEqualTo(ConfigLogic.getInstance().getProjectId())));

			//TODO: auto convert, share impl
			if (messageOrd.isPresent()) {
				MessageOrd entity = messageOrd.get();
				entity.setOrd(order);
				entity.setPrcDate(now);
				messageOrdMapper.updateByPrimaryKeySelective(entity);
			} else {
				MessageOrd entity = new MessageOrd();
				entity.setFkProjectId(ConfigLogic.getInstance().getProjectId());
				entity.setOrd(order);
				entity.setPrcDate(now);
				messageOrdMapper.insert(entity);
			}
		});
	}

	public void loadMessageDetail(MessageDto dto) {
		var httpRequestResponse = loadMessageDetail(dto.getMessageRawId());

		dto.setMessage(httpRequestResponse);
		dto.setRequestInfo(BurpApiClient.i().analyzeRequest(httpRequestResponse));
		dto.setMessageParamList(dto.getRequestInfo().getParameters().stream()
				.map(parameter -> convertParameterToDto(parameter)).collect(Collectors.toList()));

		if(httpRequestResponse.getResponse() != null) {
			dto.setResponseInfo(BurpApiClient.i().analyzeResponse(httpRequestResponse.getResponse()));
			dto.setMessageCookieList(dto.getResponseInfo().getCookies().stream()
					.map(MessageUtil::convertCookieToDto).collect(Collectors.toList()));
		}
	}

	public HttpRequestResponseDto loadMessageDetail(Integer messageRawId) {
		MessageRaw messageRaw =
			DbUtil.withSession(session -> {
				MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
				return messageRawMapper
						.selectOne(c -> c.where(MessageRawDynamicSqlSupport.id, isEqualTo(messageRawId)))
						.get();
			});

		return convertEntityToDto(messageRaw);
	}

	public void loadRepeatMaster(MessageDto messageDto) {
		MessageRaw messageRaw =
			DbUtil.withSession(session -> {
				MessageRepeatMasterMapper messageRepeatMasterMapper = session.getMapper(MessageRepeatMasterMapper.class);
				MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);

				var messageRepeatMaster = messageRepeatMasterMapper.selectOne(c -> c.where(MessageRepeatMasterDynamicSqlSupport.fkMessageId, isEqualTo(messageDto.getId())));
				if(messageRepeatMaster.isEmpty()) {
					return null;
				}

				return messageRawMapper
						.selectByPrimaryKey(messageRepeatMaster.get().getFkMessageRawId())
						.get();
			});

		if(messageRaw != null) {
			messageDto.setRepeatMasterMessage(convertEntityToDto(messageRaw));
		}
	}

	/**
	 * insert or update
	 */
	public void saveRepeatMaster(MessageDto messageDto) {
		String now = SqlUtil.now();
		DbUtil.withTransaction(session -> {
			MessageRawMapper messageRawMapper = session.getMapper(MessageRawMapper.class);
			MessageRepeatMasterMapper messageRepeatMasterMapper = session.getMapper(MessageRepeatMasterMapper.class);

			var messageRepeatMasterOptional = messageRepeatMasterMapper.selectOne(c -> c.where(MessageRepeatMasterDynamicSqlSupport.fkMessageId, isEqualTo(messageDto.getId())));
			if(messageRepeatMasterOptional.isPresent()) {
				var messageRaw = messageRawMapper.selectByPrimaryKey(messageRepeatMasterOptional.get().getFkMessageRawId()).get();
				messageRaw.setRequest(messageDto.getRepeatMasterMessage().getRequest());
				messageRaw.setResponse(messageDto.getRepeatMasterMessage().getResponse());
				messageRaw.setPrcDate(now);
				messageRawMapper.updateByPrimaryKey(messageRaw);
				return;
			}

			var messageRaw = new MessageRaw();
			messageRaw.setHost(messageDto.getMessage().getHttpService().getHost());
			messageRaw.setPort(messageDto.getMessage().getHttpService().getPort());
			messageRaw.setProtocol(messageDto.getMessage().getHttpService().getProtocol());
			messageRaw.setRequest(messageDto.getRepeatMasterMessage().getRequest());
			messageRaw.setResponse(messageDto.getRepeatMasterMessage().getResponse());
			messageRaw.setPrcDate(now);
			messageRawMapper.insert(messageRaw);

			var messageRepeatMaster = new MessageRepeatMaster();
			messageRepeatMaster.setFkMessageId(messageDto.getId());
			messageRepeatMaster.setFkMessageRawId(messageRaw.getId());
			messageRepeatMaster.setPrcDate(now);
			messageRepeatMasterMapper.insert(messageRepeatMaster);

		});
	}

}
