package okuken.iste.view.option;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;
import okuken.iste.logic.TemplateLogic;
import okuken.iste.util.UiUtil;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import javax.swing.JButton;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;

public class UserOptionsCopyTemplatesPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private List<UserOptionsCopyTemplatePanel> templatePanels = Lists.newArrayList();

	private JLabel saveMessageLabel;
	private JPanel mainPanel;
	private JScrollPane mainScrollPane;

	public UserOptionsCopyTemplatesPanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel controlPanel = new JPanel();
		FlowLayout flowLayout = (FlowLayout) controlPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		add(controlPanel, BorderLayout.NORTH);
		
		JButton addButton = new JButton(Captions.ADD);
		addButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				var templatePanel = addTemplatePanel();
				UiUtil.repaint(mainPanel);
				SwingUtilities.invokeLater(() -> {
					templatePanel.focus();
					UiUtil.scrollFor(templatePanel, mainScrollPane);
				});
			}
		});
		controlPanel.add(addButton);
		
		JButton saveButton = new JButton(Captions.SAVE);
		saveButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					save();
					UiUtil.showTemporaryMessage(saveMessageLabel, Captions.MESSAGE_SAVED);
				} catch(Exception ex) {
					UiUtil.showMessage(ex.getMessage(), saveButton);
				}
			}
		});
		controlPanel.add(saveButton);
		
		saveMessageLabel = UiUtil.createTemporaryMessageArea();
		controlPanel.add(saveMessageLabel);
		
		JLabel explainLabel = new JLabel(Captions.USER_OPTIONS_COPY_TEMPLATE_EXPLANATION);
		controlPanel.add(explainLabel);
		
		JPanel centerPanel = new JPanel();
		centerPanel.setLayout(new BorderLayout(0, 0));
		add(centerPanel, BorderLayout.CENTER);
		
		JPanel templateReferencesPanel = new JPanel();
		FlowLayout flowLayout_1 = (FlowLayout) templateReferencesPanel.getLayout();
		flowLayout_1.setAlignment(FlowLayout.LEFT);
		TemplateLogic.getInstance().getTemplateReferenceGeneralKeys().forEach(key -> {
			var referenceButton = new JButton(key);
			referenceButton.setToolTipText(Captions.COPY);
			referenceButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					UiUtil.copyToClipboard(key);
				}
			});
			templateReferencesPanel.add(referenceButton);
		});
		JScrollPane templateReferencesScrollPane = new JScrollPane(templateReferencesPanel);
		centerPanel.add(templateReferencesScrollPane, BorderLayout.NORTH);
		
		mainPanel = new JPanel();
		mainPanel.setLayout(new GridLayout(0, 1, 0, 0));
		mainScrollPane = new JScrollPane(mainPanel);
		centerPanel.add(mainScrollPane, BorderLayout.CENTER);
		
		
		load();
		Controller.getInstance().setUserOptionsCopyTemplatesPanel(this);
	}

	public void refresh() {
		for(int i = templatePanels.size() - 1; i >= 0; i--) {
			var templatePanel = templatePanels.get(i);
			mainPanel.remove(templatePanel);
			templatePanels.remove(templatePanel);
		}

		load();
		Controller.getInstance().refreshMessageTablePopupMenu();
	}

	private UserOptionsCopyTemplatePanel addTemplatePanel() {
		return addTemplatePanel(null, null, null);
	}
	private UserOptionsCopyTemplatePanel addTemplatePanel(String name, String template, String mnemonic) {
		var templatePanel = new UserOptionsCopyTemplatePanel(this, name, template, mnemonic);
		templatePanels.add(templatePanel);
		mainPanel.add(templatePanel);
		return templatePanel;
	}

	void removeTemplatePanel(UserOptionsCopyTemplatePanel templatePanel) {
		mainPanel.remove(templatePanel);
		templatePanels.remove(templatePanel);

		UiUtil.repaint(mainPanel);
	}

	void upTemplatePanel(UserOptionsCopyTemplatePanel templatePanel) {
		var currentIndex = templatePanels.indexOf(templatePanel);
		changeOrder(currentIndex - 1, currentIndex);
	}

	void downTemplatePanel(UserOptionsCopyTemplatePanel templatePanel) {
		var currentIndex = templatePanels.indexOf(templatePanel);
		changeOrder(currentIndex, currentIndex + 1);
	}

	private void changeOrder(int index1, int index2) {
		if(index1 < 0 || index2 >= templatePanels.size()) {
			return;
		}

		var target = templatePanels.get(index2);
		mainPanel.remove(target);
		templatePanels.remove(target);

		mainPanel.add(target, index1);
		templatePanels.add(index1, target);

		UiUtil.repaint(mainPanel);
	}

	private void load() {
		var loadedCopyTemplates = ConfigLogic.getInstance().getUserOptions().getCopyTemplates();
		if(loadedCopyTemplates == null) {
			return;
		}

		loadedCopyTemplates.entrySet().forEach(entry -> {
			addTemplatePanel(entry.getKey(), entry.getValue(), getMnemonic(entry.getKey()));
		});

		UiUtil.repaint(mainPanel);
	}
	private String getMnemonic(String key) {
		var loadedCopyTemplateMnemonics = ConfigLogic.getInstance().getUserOptions().getCopyTemplateMnemonics();
		if(loadedCopyTemplateMnemonics == null || !loadedCopyTemplateMnemonics.containsKey(key)) {
			return null;
		}

		return loadedCopyTemplateMnemonics.get(key);
	}

	private void save() {
		Map<String, String> copyTemplates = Maps.newLinkedHashMap();
		Map<String, String> copyTemplateMnemonics = Maps.newLinkedHashMap();
		templatePanels.forEach(templatePanel -> {
			var name = templatePanel.getTemplateName();
			if(copyTemplates.containsKey(name)) {
				throw new IllegalArgumentException("Template name must be unique.");
			}
			copyTemplates.put(name, templatePanel.getTemplateBody());
			copyTemplateMnemonics.put(name, templatePanel.getTemplateMnemonic());
		});
		ConfigLogic.getInstance().saveCopyTemplates(copyTemplates, copyTemplateMnemonics);
		Controller.getInstance().refreshMessageTablePopupMenu();
	}

}
