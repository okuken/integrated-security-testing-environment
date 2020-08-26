package okuken.iste.plugin;

import java.awt.Component;
import java.io.File;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import java.util.Map;

import com.google.common.collect.Lists;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.ICookie;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IHttpRequestResponseWithMarkers;
import burp.IHttpService;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IIntruderPayloadProcessor;
import burp.IMenuItemHandler;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IMessageEditorTabFactory;
import burp.IProxyListener;
import burp.IScanIssue;
import burp.IScanQueueItem;
import burp.IScannerCheck;
import burp.IScannerInsertionPointProvider;
import burp.IScannerListener;
import burp.IScopeChangeListener;
import burp.ISessionHandlingAction;
import burp.ITab;
import burp.ITempFile;
import burp.ITextEditor;
import okuken.iste.util.BurpUtil;

@SuppressWarnings("deprecation")
class PluginCallbacks implements IBurpExtenderCallbacks {

	private String pluginFileName;
	private String pluginName;
	private List<IContextMenuFactory> pluginContextMenuFactories;
	private List<ITab> pluginTabs;
	private IExtensionStateListener pluginStateListener;

	PluginCallbacks(String pluginFileName) {
		this.pluginFileName = pluginFileName;
	}
	String getPluginName() {
		return pluginName;
	}
	List<IContextMenuFactory> getPluginContextMenuFactories() {
		return pluginContextMenuFactories;
	}
	List<ITab> getPluginTabs() {
		return pluginTabs;
	}
	IExtensionStateListener getPluginStateListener() {
		return pluginStateListener;
	}


	@Override
	public void setExtensionName(String name) {
		pluginName = name;
	}

	@Override
	public void registerContextMenuFactory(IContextMenuFactory factory) {
		if(pluginContextMenuFactories == null) {
			pluginContextMenuFactories = Lists.newArrayList();
		}
		pluginContextMenuFactories.add(factory);
	}

	@Override
	public List<IContextMenuFactory> getContextMenuFactories() {
		return pluginContextMenuFactories;
	}

	@Override
	public void removeContextMenuFactory(IContextMenuFactory factory) {
		if(pluginContextMenuFactories == null) {
			return;
		}
		pluginContextMenuFactories.remove(factory);
	}

	@Override
	public void addSuiteTab(ITab tab) {
		if(pluginTabs == null) {
			pluginTabs = Lists.newArrayList();
		}
		pluginTabs.add(tab);
	}

	@Override
	public void removeSuiteTab(ITab tab) {
		if(pluginTabs == null) {
			return;
		}
		pluginTabs.remove(tab);
	}

	@Override
	public void saveExtensionSetting(String name, String value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public String loadExtensionSetting(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void registerExtensionStateListener(IExtensionStateListener listener) {
		this.pluginStateListener = listener;
	}

	@Override
	public String getExtensionFilename() {
		return pluginFileName;
	}


// wrap

	@Override
	public IExtensionHelpers getHelpers() {
		return BurpUtil.getCallbacks().getHelpers();
	}

	@Override
	public OutputStream getStdout() {
		return BurpUtil.getCallbacks().getStdout();
	}

	@Override
	public OutputStream getStderr() {
		return BurpUtil.getCallbacks().getStderr();
	}

	@Override
	public void printOutput(String output) {
		BurpUtil.getCallbacks().printOutput(output);
	}

	@Override
	public void printError(String error) {
		BurpUtil.getCallbacks().printError(error);
	}

	@Override
	public void customizeUiComponent(Component component) {
		BurpUtil.getCallbacks().customizeUiComponent(component);
	}

	@Override
	public IMessageEditor createMessageEditor(IMessageEditorController controller, boolean editable) {
		return BurpUtil.getCallbacks().createMessageEditor(controller, editable);
	}

	@Override
	public String[] getCommandLineArguments() {
		return BurpUtil.getCallbacks().getCommandLineArguments();
	}

	@Override
	public ITextEditor createTextEditor() {
		return BurpUtil.getCallbacks().createTextEditor();
	}

	@Override
	public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption) {
		BurpUtil.getCallbacks().sendToRepeater(host, port, useHttps, request, tabCaption);
	}

	@Override
	public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {
		BurpUtil.getCallbacks().sendToIntruder(host, port, useHttps, request);
	}

	@Override
	public void sendToIntruder(String host, int port, boolean useHttps, byte[] request,
			List<int[]> payloadPositionOffsets) {
		BurpUtil.getCallbacks().sendToIntruder(host, port, useHttps, request, payloadPositionOffsets);
	}

	@Override
	public void sendToComparer(byte[] data) {
		BurpUtil.getCallbacks().sendToComparer(data);
	}

	@Override
	public void sendToSpider(URL url) {
		BurpUtil.getCallbacks().sendToSpider(url);
	}

	@Override
	public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request) {
		return BurpUtil.getCallbacks().doActiveScan(host, port, useHttps, request);
	}

	@Override
	public IScanQueueItem doActiveScan(String host, int port, boolean useHttps, byte[] request,
			List<int[]> insertionPointOffsets) {
		return BurpUtil.getCallbacks().doActiveScan(host, port, useHttps, request, insertionPointOffsets);
	}

	@Override
	public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {
		BurpUtil.getCallbacks().doPassiveScan(host, port, useHttps, request, response);
	}

	@Override
	public IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request) {
		return BurpUtil.getCallbacks().makeHttpRequest(httpService, request);
	}

	@Override
	public byte[] makeHttpRequest(String host, int port, boolean useHttps, byte[] request) {
		return BurpUtil.getCallbacks().makeHttpRequest(host, port, useHttps, request);
	}

	@Override
	public boolean isInScope(URL url) {
		return BurpUtil.getCallbacks().isInScope(url);
	}

	@Override
	public void includeInScope(URL url) {
		BurpUtil.getCallbacks().includeInScope(url);
	}

	@Override
	public void excludeFromScope(URL url) {
		BurpUtil.getCallbacks().excludeFromScope(url);
	}

	@Override
	public void issueAlert(String message) {
		BurpUtil.getCallbacks().issueAlert(message);
	}

	@Override
	public IHttpRequestResponse[] getProxyHistory() {
		return BurpUtil.getCallbacks().getProxyHistory();
	}

	@Override
	public IHttpRequestResponse[] getSiteMap(String urlPrefix) {
		return BurpUtil.getCallbacks().getSiteMap(urlPrefix);
	}

	@Override
	public IScanIssue[] getScanIssues(String urlPrefix) {
		return BurpUtil.getCallbacks().getScanIssues(urlPrefix);
	}

	@Override
	public void generateScanReport(String format, IScanIssue[] issues, File file) {
		BurpUtil.getCallbacks().generateScanReport(format, issues, file);
	}

	@Override
	public List<ICookie> getCookieJarContents() {
		return BurpUtil.getCallbacks().getCookieJarContents();
	}

	@Override
	public void updateCookieJar(ICookie cookie) {
		BurpUtil.getCallbacks().updateCookieJar(cookie);
	}

	@Override
	public void addToSiteMap(IHttpRequestResponse item) {
		BurpUtil.getCallbacks().addToSiteMap(item);
	}

	@Override
	public void setProxyInterceptionEnabled(boolean enabled) {
		BurpUtil.getCallbacks().setProxyInterceptionEnabled(enabled);
	}

	@Override
	public String[] getBurpVersion() {
		return BurpUtil.getCallbacks().getBurpVersion();
	}

	@Override
	public String getToolName(int toolFlag) {
		return BurpUtil.getCallbacks().getToolName(toolFlag);
	}

	@Override
	public void addScanIssue(IScanIssue issue) {
		BurpUtil.getCallbacks().addScanIssue(issue);
	}

	@Override
	public IBurpCollaboratorClientContext createBurpCollaboratorClientContext() {
		return BurpUtil.getCallbacks().createBurpCollaboratorClientContext();
	}

	@Override
	public String[][] getParameters(byte[] request) {
		return BurpUtil.getCallbacks().getParameters(request);
	}

	@Override
	public String[] getHeaders(byte[] message) {
		return BurpUtil.getCallbacks().getHeaders(message);
	}

	@Override
	public void registerHttpListener(IHttpListener listener) {
		BurpUtil.getCallbacks().registerHttpListener(listener);
	}

	@Override
	public void registerProxyListener(IProxyListener listener) {
		BurpUtil.getCallbacks().registerProxyListener(listener);
	}

	@Override
	public void registerScannerListener(IScannerListener listener) {
		BurpUtil.getCallbacks().registerScannerListener(listener);
	}

	@Override
	public void registerScopeChangeListener(IScopeChangeListener listener) {
		BurpUtil.getCallbacks().registerScopeChangeListener(listener);
	}

	@Override
	public void registerMessageEditorTabFactory(IMessageEditorTabFactory factory) {
		BurpUtil.getCallbacks().registerMessageEditorTabFactory(factory);
	}

	@Override
	public void registerScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {
		BurpUtil.getCallbacks().registerScannerInsertionPointProvider(provider);
	}

	@Override
	public void registerScannerCheck(IScannerCheck check) {
		BurpUtil.getCallbacks().registerScannerCheck(check);
	}

	@Override
	public void registerIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {
		BurpUtil.getCallbacks().registerIntruderPayloadGeneratorFactory(factory);
	}

	@Override
	public void registerIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {
		BurpUtil.getCallbacks().registerIntruderPayloadProcessor(processor);
	}

	@Override
	public void registerSessionHandlingAction(ISessionHandlingAction action) {
		BurpUtil.getCallbacks().registerSessionHandlingAction(action);
	}

	@Override
	public void registerMenuItem(String menuItemCaption, IMenuItemHandler menuItemHandler) {
		BurpUtil.getCallbacks().registerMenuItem(menuItemCaption, menuItemHandler);
	}


// unsupported

	@Override
	public List<IExtensionStateListener> getExtensionStateListeners() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeExtensionStateListener(IExtensionStateListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IHttpListener> getHttpListeners() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeHttpListener(IHttpListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IProxyListener> getProxyListeners() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeProxyListener(IProxyListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IScannerListener> getScannerListeners() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeScannerListener(IScannerListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IScopeChangeListener> getScopeChangeListeners() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeScopeChangeListener(IScopeChangeListener listener) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IMessageEditorTabFactory> getMessageEditorTabFactories() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeMessageEditorTabFactory(IMessageEditorTabFactory factory) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IScannerInsertionPointProvider> getScannerInsertionPointProviders() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeScannerInsertionPointProvider(IScannerInsertionPointProvider provider) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IScannerCheck> getScannerChecks() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeScannerCheck(IScannerCheck check) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IIntruderPayloadGeneratorFactory> getIntruderPayloadGeneratorFactories() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeIntruderPayloadGeneratorFactory(IIntruderPayloadGeneratorFactory factory) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<IIntruderPayloadProcessor> getIntruderPayloadProcessors() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeIntruderPayloadProcessor(IIntruderPayloadProcessor processor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<ISessionHandlingAction> getSessionHandlingActions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeSessionHandlingAction(ISessionHandlingAction action) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreState(File file) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void saveState(File file) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Map<String, String> saveConfig() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void loadConfig(Map<String, String> config) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String saveConfigAsJson(String... configPaths) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void loadConfigFromJson(String config) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExtensionBapp() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void exitSuite(boolean promptUser) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ITempFile saveToTempFile(byte[] buffer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public IHttpRequestResponsePersisted saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse) {
		throw new UnsupportedOperationException();
	}

	@Override
	public IHttpRequestResponseWithMarkers applyMarkers(IHttpRequestResponse httpRequestResponse,
			List<int[]> requestMarkers, List<int[]> responseMarkers) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void unloadExtension() {
		throw new UnsupportedOperationException();
	}

}
