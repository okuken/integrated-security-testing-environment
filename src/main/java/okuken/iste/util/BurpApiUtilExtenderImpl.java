package okuken.iste.util;

import java.awt.Component;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.IResponseInfo;
import okuken.iste.dto.HttpMessageEditorController;
import okuken.iste.IntegratedSecurityTestingEnvironment;
import okuken.iste.dto.HttpCookieDto;
import okuken.iste.dto.HttpMessageEditor;
import okuken.iste.dto.HttpRequestInfoDto;
import okuken.iste.dto.HttpRequestParameterDto;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpResponseInfoDto;
import okuken.iste.dto.HttpServiceDto;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.SuiteTab;

public class BurpApiUtilExtenderImpl extends BurpApiUtil {

	private final IBurpExtenderCallbacks callbacks;
	private final IExtensionHelpers helper;

	BurpApiUtilExtenderImpl(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helper = callbacks.getHelpers();
	}

	@Override
	public String[] getBurpVersion() {
		return callbacks.getBurpVersion();
	}
	@Override
	public OutputStream getStdout() {
		return callbacks.getStdout();
	}
	@Override
	public OutputStream getStderr() {
		return callbacks.getStderr();
	}
	@Override
	public void printError(String error) {
		callbacks.printError(error);
	}
	@Override
	public void issueAlert(String message) {
		callbacks.issueAlert(message);
	}

	@Override
	public void setExtensionName(String name) {
		callbacks.setExtensionName(name);
	}

	@Override
	public void addSuiteTab(SuiteTab tab) {
		callbacks.addSuiteTab(tab);
	}
	@Override
	public void registerContextMenuFactory(ContextMenuFactory factory) {
		callbacks.registerContextMenuFactory(factory);
	}
	@Override
	public void registerExtensionStateListener(IntegratedSecurityTestingEnvironment listener) {
		callbacks.registerExtensionStateListener(listener);
	}
	@Override
	public void unloadExtension() {
		callbacks.unloadExtension();
	}

	@Override
	public void saveExtensionSetting(String name, String value) {
		callbacks.saveExtensionSetting(name, value);
	}
	@Override
	public String loadExtensionSetting(String name) {
		return callbacks.loadExtensionSetting(name);
	}

	@Override
	public boolean isInScope(URL url) {
		return callbacks.isInScope(url);
	}

	@Override
	public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) {
		callbacks.sendToRepeater(host, port, useHttps, request, tabCaption);
	}
	@Override
	public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {
		callbacks.sendToIntruder(host, port, useHttps, request);
	}
	@Override
	public void sendToComparer(byte[] data) {
		callbacks.sendToComparer(data);
	}

	@Override
	public void doActiveScan(String host, int port, boolean useHttps, byte[] request) {
		callbacks.doActiveScan(host, port, useHttps, request);
	}
	@Override
	public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {
		callbacks.doPassiveScan(host, port, useHttps, request, response);
	}

	@Override
	public int getProxyHistorySize() {
		return callbacks.getProxyHistory().length;
	}
	@Override
	public List<HttpRequestResponseDto> getProxyHistory(List<Integer> indexes) {
		var proxyHistory = callbacks.getProxyHistory();
		return indexes.stream()
				.map(index -> proxyHistory[index])
				.filter(message -> message.getRequest() != null)
				.map(message -> convertHttpRequestResponseToDto(message))
				.collect(Collectors.toList());
	}

	@Override
	public HttpRequestInfoDto analyzeRequest(HttpRequestResponseDto request) {
		var requestInfo = helper.analyzeRequest(convertHttpRequestResponseDtoToOrg(request));
		return convertToDto(requestInfo);
	}
	@Override
	public HttpRequestInfoDto analyzeRequest(byte[] request) {
		var requestInfo = helper.analyzeRequest(request);
		return convertToDto(requestInfo);
	}
	private HttpRequestInfoDto convertToDto(IRequestInfo requestInfo) {
		var ret = ReflectionUtil.copyProperties(new HttpRequestInfoDto(), requestInfo);
		ret.setParameters(requestInfo.getParameters().stream()
				.map(param -> ReflectionUtil.copyProperties(new HttpRequestParameterDto(), param))
				.collect(Collectors.toList()));
		return ret;
	}

	@Override
	public HttpResponseInfoDto analyzeResponse(byte[] response) {
		var responseInfo = helper.analyzeResponse(response);
		return convertToDto(responseInfo);
	}
	private HttpResponseInfoDto convertToDto(IResponseInfo responseInfo) {
		var ret = ReflectionUtil.copyProperties(new HttpResponseInfoDto(), responseInfo);
		ret.setCookies(responseInfo.getCookies().stream()
				.map(cookie -> ReflectionUtil.copyProperties(new HttpCookieDto(), cookie))
				.collect(Collectors.toList()));
		return ret;
	}

	@Override
	public HttpRequestResponseDto makeHttpRequest(HttpServiceDto httpService, byte[] request) {
		return convertHttpRequestResponseToDto(
				callbacks.makeHttpRequest(httpService, request));
	}

	@Override
	public byte[] buildHttpMessage(List<String> headers, byte[] body) {
		return helper.buildHttpMessage(headers, body);
	}

	@Override
	public HttpRequestParameterDto buildParameter(String name, String value, byte type) {
		return ReflectionUtil.copyProperties(new HttpRequestParameterDto(),
				helper.buildParameter(name, value, type));
	}

	@Override
	public byte[] addParameter(byte[] request, HttpRequestParameterDto parameter) {
		return helper.addParameter(request, parameter);
	}
	@Override
	public byte[] removeParameter(byte[] request, HttpRequestParameterDto parameter) {
		return helper.removeParameter(request, parameter);
	}
	@Override
	public byte[] updateParameter(byte[] request, HttpRequestParameterDto parameter) {
		return helper.updateParameter(request, parameter);
	}

	@Override
	public String urlEncode(String data) {
		return helper.urlEncode(data);
	}

	@Override
	public void customizeUiComponent(Component component) {
		callbacks.customizeUiComponent(component);
	}

	@Override
	public HttpMessageEditor createMessageEditor(HttpMessageEditorController controller, boolean editable) {
		var messageEditor = callbacks.createMessageEditor(new IMessageEditorController() {
			@Override
			public byte[] getRequest() {
				return controller.getRequest();
			}
			@Override
			public byte[] getResponse() {
				return controller.getResponse();
			}
			@Override
			public IHttpService getHttpService() {
				return controller.getHttpService();
			}
		}, editable);

		return new HttpMessageEditor() {
			@Override
			public void setMessage(byte[] message, boolean isRequest) {
				messageEditor.setMessage(message, isRequest);
			}
			@Override
			public boolean isMessageModified() {
				return messageEditor.isMessageModified();
			}
			@Override
			public int[] getSelectionBounds() {
				return messageEditor.getSelectionBounds();
			}
			@Override
			public byte[] getSelectedData() {
				return messageEditor.getSelectedData();
			}
			@Override
			public byte[] getMessage() {
				return messageEditor.getMessage();
			}
			@Override
			public Component getComponent() {
				return messageEditor.getComponent();
			}
		};
	}

	@Override
	public HttpRequestResponseDto convertHttpRequestResponseToDto(Object iHttpRequestResponse) {
		var httpRequestResponse = (IHttpRequestResponse)iHttpRequestResponse;
		var httpService = httpRequestResponse.getHttpService();

		var ret = new HttpRequestResponseDto(
				httpRequestResponse.getRequest(),
				httpRequestResponse.getResponse(),
				new HttpServiceDto(httpService.getHost(), httpService.getPort(), httpService.getProtocol()));

		ret.setComment(httpRequestResponse.getComment());
		ret.setHighlight(httpRequestResponse.getHighlight());

		return ret;
	}

	private IHttpRequestResponse convertHttpRequestResponseDtoToOrg(HttpRequestResponseDto dto) {
		return new IHttpRequestResponse() {
			@Override
			public void setResponse(byte[] message) {
				dto.setResponse(message);
			}
			@Override
			public void setRequest(byte[] message) {
				dto.setRequest(message);
			}
			@Override
			public void setHttpService(IHttpService httpService) {
				dto.setHttpService(new HttpServiceDto(httpService.getHost(), httpService.getPort(), httpService.getProtocol()));
			}
			@Override
			public void setHighlight(String color) {
				dto.setHighlight(color);
			}
			@Override
			public void setComment(String comment) {
				dto.setComment(comment);
			}
			@Override
			public byte[] getResponse() {
				return dto.getResponse();
			}
			@Override
			public byte[] getRequest() {
				return dto.getRequest();
			}
			@Override
			public IHttpService getHttpService() {
				return dto.getHttpService();
			}
			@Override
			public String getHighlight() {
				return dto.getHighlight();
			}
			@Override
			public String getComment() {
				return dto.getComment();
			}
		};
	}

}
