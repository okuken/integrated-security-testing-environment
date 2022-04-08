package okuken.iste.view.common;

import javax.swing.JPanel;
import javax.swing.JScrollPane;

import com.google.common.collect.Lists;

import okuken.iste.consts.Colors;
import okuken.iste.util.BurpUtil;
import okuken.iste.util.UiUtil;

import java.awt.GridLayout;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;

import java.awt.Component;
import java.awt.FlowLayout;

public class MultipleSelectorPanel<T> extends JPanel {

	private static final long serialVersionUID = 1L;

	private List<T> candidates;
	private List<JCheckBox> checkboxes = Lists.newArrayList();

	private JPanel mainPanel;

	public MultipleSelectorPanel(List<T> candidates) {
		this.candidates = candidates;
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBorder(null);
		add(scrollPane);
		
		mainPanel = new JPanel();
		scrollPane.setViewportView(mainPanel);
		mainPanel.setLayout(new GridLayout(0, 1, 0, 0));
		
		JPanel togglerPanel = new JPanel();
		togglerPanel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Colors.BLOCK_BORDER));
		FlowLayout flowLayout = (FlowLayout) togglerPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		flowLayout.setHgap(0);
		flowLayout.setVgap(0);
		mainPanel.add(togglerPanel);
		
		JCheckBox togglerCheckbox = new JCheckBox();
		togglerCheckbox.addActionListener(e -> {
			checkboxes.forEach(checkbox -> checkbox.setSelected(togglerCheckbox.isSelected()));
		});
		togglerPanel.add(togglerCheckbox);
		
		init();
	}
	private void init() {
		candidates.forEach(candidate -> {
			JCheckBox checkbox = new JCheckBox(candidate.toString());
			checkboxes.add(checkbox);
			mainPanel.add(checkbox);
		});
	}

	public List<T> showDialog(String title, Component parent) {
		BurpUtil.getCallbacks().customizeUiComponent(this);

		if(UiUtil.showOptionDialog(
				parent,
				this,
				title,
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, null, null) == 0) {

			return IntStream.range(0, candidates.size())
						.filter(i -> checkboxes.get(i).isSelected())
						.mapToObj(candidates::get)
						.collect(Collectors.toList());
		}
		return null;
	}

}
