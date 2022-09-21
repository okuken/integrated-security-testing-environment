package okuken.iste.util;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import com.google.common.collect.Lists;
import com.google.gson.Gson;

import burp.ICookie;
import burp.IParameter;
import burp.IResponseInfo;
import okuken.iste.dto.AuthAccountDto;
import okuken.iste.dto.MessageChainNodeReqpDto;
import okuken.iste.dto.MessageChainTokenTransferSettingDto;
import okuken.iste.dto.MessageCookieDto;
import okuken.iste.dto.MessageDto;
import okuken.iste.dto.MessageRequestParamDto;
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

		if(paramType == RequestParameterType.HEADER) {
			return applyHeaderPayload(request, paramName, paramValue);
		}

		if(!BurpUtil.getHelpers().analyzeRequest(request).getParameters().stream().anyMatch(p -> 
				p.getType() == paramType.getBurpId() && StringUtils.equals(p.getName(), paramName))) {
			return request;
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

	private static byte[] applyHeaderPayload(byte[] request, String headerName, String value) {
		var requestInfo = BurpUtil.getHelpers().analyzeRequest(request);

		var headerPrefix = headerName + ": ";
		var appliedHeaders = requestInfo.getHeaders().stream().map(header -> header.startsWith(headerPrefix) ? headerPrefix + value : header).collect(Collectors.toList());
		var body = HttpUtil.extractMessageBody(request, requestInfo.getBodyOffset());
		return BurpUtil.getHelpers().buildHttpMessage(appliedHeaders, body);
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

	public static List<MessageRequestParamDto> extractRequestParams(List<MessageDto> messageDtos) {
		return messageDtos.stream()
				.flatMap(messageDto -> extractRequestParams(messageDto).stream())
				.sorted()
				.distinct()
				.collect(Collectors.toList());
	}
	public static List<MessageRequestParamDto> extractRequestParams(MessageDto messageDto) {
		var parameters = messageDto.getRequestInfo().getParameters().stream()
				.filter(MessageUtil::isRequestParameter)
				.map(param -> new MessageRequestParamDto(RequestParameterType.getByBurpId(param.getType()), param.getName()));

		var headers = messageDto.getRequestInfo().getHeaders().stream()
				.map(header -> header.split(":"))
				.filter(headerSplitted -> headerSplitted.length >= 2)
				.map(headerSplitted -> headerSplitted[0].trim())
				.filter(headerName -> !StringUtils.equals(headerName, "Cookie"))
				.map(headerName -> new MessageRequestParamDto(RequestParameterType.HEADER, headerName));

		return Stream.concat(parameters, headers).sorted().distinct().collect(Collectors.toList());
	}
	private static boolean isRequestParameter(IParameter param) {
		var paramType = param.getType();
		return paramType == RequestParameterType.URL.getBurpId() ||
				paramType == RequestParameterType.BODY.getBurpId();
	}


	/**
	 * CAUTION: not support to extract multibyte character
	 */
	public static String extractResponseParam(byte[] response, ResponseParameterType paramType, String paramName) {
		if(!paramType.isExtractable()) {
			throw new IllegalArgumentException("The parameter type is not extractable: " + paramType);
		}
		if(paramType == ResponseParameterType.REGEX) {
			return RegexUtil.extractOneGroup(response, paramName);
		}
		if(paramType == ResponseParameterType.HTML_TAG) {
			return extractResponseHtmlTagValue(response, paramName);
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

	public static String extractResponseHtmlTagValue(String responseStr, String settingString) {
		return extractResponseHtmlTagValueImpl(parseResponseHtml(responseStr), settingString);
	}
	public static String extractResponseHtmlTagValue(byte[] response, String settingString) {
		return extractResponseHtmlTagValueImpl(parseResponseHtml(response), settingString);
	}
	private static String extractResponseHtmlTagValueImpl(Optional<Document> docOptional, String settingString) {
		if(docOptional.isEmpty()) {
			return null;
		}
		var doc = docOptional.get();

		if(!judgeIsValidExtractHtmlTagSetting(settingString)) {
			return null;
		}
		var separaterIndex = settingString.lastIndexOf(MessageChainTokenTransferSettingDto.SETTING_SEPARATER);
		var selector = settingString.substring(0, separaterIndex);
		var valueAttrName = settingString.substring(separaterIndex + 1);

		try {
			var element = doc.selectFirst(selector);
			if(element == null) {
				return null;
			}
	
			var ret = element.attr(valueAttrName);
			return StringUtils.isNotEmpty(ret) ? ret : null;

		} catch (Exception e) {
			BurpUtil.printStderr(e);
			return null;
		}
	}

	public static boolean judgeIsValidExtractHtmlTagSetting(String settingString) {
		var separaterIndex = settingString.lastIndexOf(MessageChainTokenTransferSettingDto.SETTING_SEPARATER);
		if(separaterIndex < 0 || separaterIndex >= settingString.length() - 1) {
			return false;
		}
		return true;
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

	public static Optional<String> convertToResponseHtmlString(byte[] response) {
		var responseInfo = BurpUtil.getHelpers().analyzeResponse(response);
		if(!isHtml(responseInfo.getStatedMimeType())) {
			return Optional.empty();
		}
		return Optional.of(HttpUtil.convertMessageBytesToString(response, responseInfo.getHeaders(), responseInfo.getBodyOffset()));
	}

	public static Optional<Document> parseResponseHtml(byte[] response) {
		return parseResponseHtml(convertToResponseHtmlString(response).orElse(""));
	}
	public static Optional<Document> parseResponseHtml(MessageDto messageDto) {
		if(!isHtml(messageDto.getMimeType())) {
			return Optional.empty();
		}
		return parseResponseHtml(messageDto.getResponseStr());
	}
	private static Optional<Document> parseResponseHtml(String response) {
		if(StringUtils.isEmpty(response)) {
			return Optional.empty();
		}

		try {
			return Optional.of(Jsoup.parse(HttpUtil.extractMessageBody(response)));
		} catch (Exception e) {
			BurpUtil.printStderr(e);
			return Optional.empty();
		}
	}
	private static boolean isHtml(String mimeType) {
		return "HTML".equals(mimeType);
	}

}
