package okuken.iste.view;

import java.awt.Component;

import burp.ITab;
import okuken.iste.client.BurpApiClient;
import okuken.iste.consts.Captions;

public class SuiteTab implements ITab {

	private SuitePanel suitePanel;

	public SuiteTab() {
		SuitePanel suitePanel = new SuitePanel();
		BurpApiClient.i().customizeUiComponent(suitePanel);
		this.suitePanel = suitePanel;
	}

	@Override
	public String getTabCaption() {
		return Captions.TAB_SUITE;
	}

	@Override
	public Component getUiComponent() {
		return suitePanel;
	}

}