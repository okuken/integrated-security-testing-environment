package okuken.iste.util;

import java.awt.Component;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.MontoyaApi;

import okuken.iste.ExtensionStateListener;
import okuken.iste.dto.HttpMessageEditorController;
import okuken.iste.dto.HttpMessageEditor;
import okuken.iste.dto.HttpRequestInfoDto;
import okuken.iste.dto.HttpRequestParameterDto;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpResponseInfoDto;
import okuken.iste.dto.HttpServiceDto;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.SuiteTab;

public abstract class BurpApiUtil {

	private static BurpApiUtil instance;

	public static void init(MontoyaApi montoyaApi) {
		checkDuplication();
		instance = new BurpApiUtilMontoyaImpl(montoyaApi);
	}
	public static void init(IBurpExtenderCallbacks burpExtenderCallbacks) {
		checkDuplication();
		instance = new BurpApiUtilExtenderImpl(burpExtenderCallbacks);
	}
	private static void checkDuplication() {
		if(instance != null) {
			throw new IllegalStateException("Duplicated init");
		}
	}


	public static BurpApiUtil i() {
		return instance;
	}


	public abstract String[] getBurpVersion();
	public abstract OutputStream getStdout();
	public abstract OutputStream getStderr();
	public abstract void printError(String error);
	public abstract void issueAlert(String message);

	public abstract void setExtensionName(String name);
	public abstract void addSuiteTab(SuiteTab tab);
	public abstract void registerContextMenuFactory(ContextMenuFactory factory);
	public abstract void registerExtensionStateListener(ExtensionStateListener listener);
	public abstract void unloadExtension();

	public abstract void saveExtensionSetting(String name, String value);
	public abstract String loadExtensionSetting(String name);

	public abstract boolean isInScope(URL url);

	public abstract void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption);
	public abstract void sendToIntruder(String host, int port, boolean useHttps, byte[] request);
	public abstract void sendToComparer(byte[] data);

	public abstract void doActiveScan(String host, int port, boolean useHttps, byte[] request);
	public abstract void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response);

	public abstract int getProxyHistorySize();
	public abstract List<HttpRequestResponseDto> getProxyHistory(List<Integer> indexes);

	public abstract HttpRequestInfoDto analyzeRequest(HttpRequestResponseDto request);
	public abstract HttpRequestInfoDto analyzeRequest(byte[] request);
	public abstract HttpResponseInfoDto analyzeResponse(byte[] response);

	public abstract HttpRequestResponseDto makeHttpRequest(HttpServiceDto httpService, byte[] request);

	public abstract byte[] buildHttpMessage(List<String> headers, byte[] body);
	public abstract HttpRequestParameterDto buildParameter(String name, String value, byte type);
	public abstract byte[] addParameter(byte[] request, HttpRequestParameterDto parameter);
	public abstract byte[] removeParameter(byte[] request, HttpRequestParameterDto parameter);
	public abstract byte[] updateParameter(byte[] request, HttpRequestParameterDto parameter);

	public abstract String urlEncode(String data);

	public abstract void customizeUiComponent(Component component);
	public abstract HttpMessageEditor createMessageEditor(HttpMessageEditorController controller, boolean editable);

	public abstract HttpRequestResponseDto convertHttpRequestResponseToDto(Object httpRequestResponse);

}
