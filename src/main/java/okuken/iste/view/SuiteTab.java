package okuken.iste.view;

import java.awt.Component;

import burp.ITab;
import okuken.iste.consts.Captions;
import okuken.iste.util.BurpUtil;

public class SuiteTab implements ITab {

	private SuitePanel suitePanel;

	public SuiteTab() {
		SuitePanel suitePanel = new SuitePanel();
		BurpUtil.getCallbacks().customizeUiComponent(suitePanel);
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