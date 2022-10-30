package okuken.iste.util;

import java.awt.Component;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;

import burp.api.montoya.MontoyaApi;
import okuken.iste.IntegratedSecurityTestingEnvironment;
import okuken.iste.dto.HttpMessageEditor;
import okuken.iste.dto.HttpMessageEditorController;
import okuken.iste.dto.HttpRequestInfoDto;
import okuken.iste.dto.HttpRequestParameterDto;
import okuken.iste.dto.HttpRequestResponseDto;
import okuken.iste.dto.HttpResponseInfoDto;
import okuken.iste.dto.HttpServiceDto;
import okuken.iste.view.ContextMenuFactory;
import okuken.iste.view.SuiteTab;

public class BurpApiUtilMontoyaImpl extends BurpApiUtil {

	private final MontoyaApi api;

	BurpApiUtilMontoyaImpl(MontoyaApi api) {
		this.api = api;
	}

	@Override
	public String[] getBurpVersion() {
		//TODO: impl
		return null;
	}
	@Override
	public OutputStream getStdout() {
		//TODO: impl
		return null;
	}
	@Override
	public OutputStream getStderr() {
		//TODO: impl
		return null;
	}
	@Override
	public void printError(String error) {
		//TODO: impl
	}
	@Override
	public void issueAlert(String message) {
		//TODO: impl
	}

	@Override
	public void setExtensionName(String name) {
		api.misc().setExtensionName(name);
	}

	@Override
	public void addSuiteTab(SuiteTab suiteTab) {
		api.userInterface().registerSuiteTab(suiteTab.getTabCaption(), suiteTab.getUiComponent());
	}
	@Override
	public void registerContextMenuFactory(ContextMenuFactory factory) {
		api.userInterface().registerContextMenuItemsProvider(factory);
	}
	@Override
	public void registerExtensionStateListener(IntegratedSecurityTestingEnvironment listener) {
		api.misc().registerExtensionUnloadHandler(listener);
	}
	@Override
	public void unloadExtension() {
		//TODO: impl
	}

	@Override
	public void saveExtensionSetting(String name, String value) {
		//TODO: impl
	}
	@Override
	public String loadExtensionSetting(String name) {
		//TODO: impl
		return null;
	}

	@Override
	public boolean isInScope(URL url) {
		//TODO: impl
		return false;
	}

	@Override
	public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) {
		//TODO: impl
	}
	@Override
	public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {
		//TODO: impl
	}
	@Override
	public void sendToComparer(byte[] data) {
		//TODO: impl
	}

	@Override
	public void doActiveScan(String host, int port, boolean useHttps, byte[] request) {
		//TODO: impl
	}
	@Override
	public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {
		//TODO: impl
	}

	@Override
	public int getProxyHistorySize() {
		//TODO: impl
		return -1;
	}
	@Override
	public List<HttpRequestResponseDto> getProxyHistory(List<Integer> indexes) {
		//TODO: impl
		return null;
	}

	@Override
	public HttpRequestInfoDto analyzeRequest(HttpRequestResponseDto request) {
		//TODO: impl
		return null;
	}
	@Override
	public HttpRequestInfoDto analyzeRequest(byte[] request) {
		//TODO: impl
		return null;
	}

	@Override
	public HttpResponseInfoDto analyzeResponse(byte[] response) {
		//TODO: impl
		return null;
	}

	@Override
	public HttpRequestResponseDto makeHttpRequest(HttpServiceDto httpService, byte[] request) {
		//TODO: impl
		return null;
	}

	@Override
	public byte[] buildHttpMessage(List<String> headers, byte[] body) {
		//TODO: impl
		return null;
	}

	@Override
	public HttpRequestParameterDto buildParameter(String name, String value, byte type) {
		//TODO: impl
		return null;
	}

	@Override
	public byte[] addParameter(byte[] request, HttpRequestParameterDto parameter) {
		//TODO: impl
		return null;
	}
	@Override
	public byte[] removeParameter(byte[] request, HttpRequestParameterDto parameter) {
		//TODO: impl
		return null;
	}
	@Override
	public byte[] updateParameter(byte[] request, HttpRequestParameterDto parameter) {
		//TODO: impl
		return null;
	}

	@Override
	public String urlEncode(String data) {
		//TODO: impl
		return null;
	}

	@Override
	public void customizeUiComponent(Component component) {
		//TODO: impl
	}

	@Override
	public HttpMessageEditor createMessageEditor(HttpMessageEditorController controller, boolean editable) {
		//TODO: impl
		return null;
	}

	@Override
	public HttpRequestResponseDto convertHttpRequestResponseToDto(Object iHttpRequestResponse) {
		//TODO: impl
		return null;
	}

}
