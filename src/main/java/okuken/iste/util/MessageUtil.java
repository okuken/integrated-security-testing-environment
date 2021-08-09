package okuken.iste.util;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;
import com.google.gson.Gson;

import burp.ICookie;
import burp.IParameter;
import burp.IResponseInfo;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.dto.MessageCookieDto;
import okuken.iste.dto.MessageResponseParamDto;
import okuken.iste.dto.PayloadDto;
import okuken.iste.enums.RequestParameterType;
import okuken.iste.enums.ResponseParameterType;

public class MessageUtil {

	public static byte[] applyPayload(byte[] request, RequestParameterType paramType, String paramName, String paramValue) {
		if(!paramType.isAppliable()) {
			throw new IllegalArgumentException("The parameter type is not appliable: " + paramType);
		}
		if(paramValue == null) {
			return request;
		}

		if(paramType == RequestParameterType.REGEX) {
			return applyRegexPayload(request, paramName, paramValue);
		}

		var parameter = BurpUtil.getHelpers().buildParameter(paramName, paramValue, paramType.getBurpId());
		switch (paramType) {
		case COOKIE:
			return applyCookiePayload(request, parameter);
		default:
			return BurpUtil.getHelpers().updateParameter(request, parameter);
		}
	}

	/**
	 * CAUTION: not support to apply multibyte character
	 */
	private static byte[] applyRegexPayload(byte[] request, String regex, String paramValue) {
		var requestStr = new String(request, ByteUtil.DEFAULT_SINGLE_BYTE_CHARSET);
		var appliedRequestStr = RegexUtil.replaceOneGroup(requestStr, regex, paramValue);
		return updateContentLength(appliedRequestStr.getBytes(ByteUtil.DEFAULT_SINGLE_BYTE_CHARSET));
	}

	public static byte[] applyCookiePayload(byte[] request, IParameter parameter) {
		var ret = BurpUtil.getHelpers().removeParameter(request, parameter);
		ret = HttpUtil.removeDustAtEndOfCookieHeader(ret); // bug recovery
		return BurpUtil.getHelpers().addParameter(ret, parameter);
	}

//	private static byte[] applyHeaderPayload(byte[] request, IParameter parameter) {
//		//TODO: generalize...
//		var authorizationHeader = HttpUtil.createAuthorizationBearerHeader(authAccountDto.getSessionId());
//
//		var requestInfo = BurpUtil.getHelpers().analyzeRequest(request);
//		var headers = requestInfo.getHeaders();
//		var authorizationHeaderIndex = IntStream.range(0, headers.size()).filter(i -> HttpUtil.judgeIsAuthorizationBearerHeader(headers.get(i))).findFirst();
//		if(authorizationHeaderIndex.isPresent()) {
//			headers.remove(authorizationHeaderIndex.getAsInt());
//			headers.add(authorizationHeaderIndex.getAsInt(), authorizationHeader);
//		} else {
//			headers.add(authorizationHeader);
//		}
//
//		var body = HttpUtil.extractMessageBody(request, requestInfo.getBodyOffset());
//		return BurpUtil.getHelpers().buildHttpMessage(headers, body);
//	}

	public static byte[] applyPayloads(byte[] request, List<PayloadDto> payloadDtos) {
		byte[] ret = request;
		for(var payloadDto: payloadDtos) {
			ret = applyPayload(ret, payloadDto);
		}
		return ret;
	}
	public static byte[] applyPayload(byte[] request, PayloadDto payloadDto) {
		return applyPayload(request, payloadDto.getTargetParamType(), payloadDto.getTargetParamName(), payloadDto.getPayload());
	}

	public static byte[] applyPayloads(byte[] request, List<MessageChainNodeReqpDto> reqpDtos, Map<String, String> vars, AuthAccountDto authAccountDto) {
		byte[] ret = request;
		for(var reqpDto: reqpDtos) {
			ret = applyPayload(ret, reqpDto, vars, authAccountDto);
		}
		return ret;
	}
	public static byte[] applyPayload(byte[] request, MessageChainNodeReqpDto reqpDto, Map<String, String> vars, AuthAccountDto authAccountDto) {
		var varName = reqpDto.getSourceName();
		switch (reqpDto.getSourceType()) {
		case VAR:
			if(!vars.containsKey(varName)) {
				return request;
			}

			return applyPayload(request, reqpDto.getParamType(), reqpDto.getParamName(), EncodeUtil.encode(vars.get(varName), reqpDto.getEncode()));

		case AUTH_ACCOUNT_TABLE:
			if(authAccountDto == null) {
				return request;
			}

			var varValue = authAccountDto.getField(varName);
			if(varValue == null) {
				return request;
			}

			return applyPayload(request, reqpDto.getParamType(), reqpDto.getParamName(), EncodeUtil.encode(varValue, reqpDto.getEncode()));

		default:
			throw new UnsupportedOperationException(reqpDto.getSourceType().name());
		}
	}

	public static byte[] updateContentLength(byte[] request) {
		var requestInfo = BurpUtil.getHelpers().analyzeRequest(request);
		return BurpUtil.getHelpers().buildHttpMessage(requestInfo.getHeaders(), HttpUtil.extractMessageBody(request, requestInfo.getBodyOffset()));
	}

	/**
	 * CAUTION: not support to extract multibyte character
	 */
	public static String extractResponseParam(byte[] response, ResponseParameterType paramType, String paramName) {
		if(!paramType.isExtractable()) {
			throw new IllegalArgumentException("The parameter type is not extractable: " + paramType);
		}
		if(paramType == ResponseParameterType.REGEX) {
			return RegexUtil.extractOneGroup(new String(response, ByteUtil.DEFAULT_SINGLE_BYTE_CHARSET), paramName);
		}

		var paramOptional = extractResponseCandidateParams(response, paramType).stream()
				.filter(sessionIdParam -> sessionIdParam.getName().equals(paramName))
				.findFirst();
		if(paramOptional.isEmpty()) {
			return null;
		}
		return paramOptional.get().getValue();
	}
	private static List<MessageResponseParamDto> extractResponseCandidateParams(byte[] response, ResponseParameterType paramType) {
		switch (paramType) {
			case COOKIE:
				return BurpUtil.getHelpers().analyzeResponse(response).getCookies().stream()
					.map(MessageUtil::convertCookieToDto)
					.collect(Collectors.toList());
			case JSON:
				return convertJsonResponseToDto(
						response,
						BurpUtil.getHelpers().analyzeResponse(response));
			default:
				return Lists.newArrayList();
		}
	}

	public static short extractResponseStatus(byte[] response) {
		return response != null ? BurpUtil.getHelpers().analyzeResponse(response).getStatusCode() : -1;
	}

	public static int extractResponseLength(byte[] response) {
		return response != null ? response.length : 0;
	}

	public static MessageCookieDto convertCookieToDto(ICookie cookie) {
		MessageCookieDto cookieDto = new MessageCookieDto();
		cookieDto.setDomain(cookie.getDomain());
		cookieDto.setPath(cookie.getPath());
		cookieDto.setExpiration(cookie.getExpiration());
		cookieDto.setName(cookie.getName());
		cookieDto.setValue(cookie.getValue());
		return cookieDto;
	}

	@SuppressWarnings("unchecked")
	public static List<MessageResponseParamDto> convertJsonResponseToDto(byte[] response, IResponseInfo responseInfo) {
		var responseBody = HttpUtil.extractMessageBody(response, responseInfo.getBodyOffset());
		var responseBodyStr = new String(responseBody, Optional.ofNullable(ByteUtil.detectEncoding(response)).orElse(HttpUtil.DEFAULT_HTTP_BODY_CHARSET));
		Map<String, Object> json = new Gson().fromJson(responseBodyStr, Map.class);

		//TODO: support multiple levels json
		return json.entrySet().stream().map(entry -> {
			var dto = new MessageResponseParamDto();
			dto.setName(entry.getKey());
			dto.setValue(entry.getValue().toString());
			dto.setType(ResponseParameterType.JSON);
			return dto;
		}).collect(Collectors.toList());
	}

}
