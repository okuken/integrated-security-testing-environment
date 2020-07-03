package okuken.iste.view.option;

import javax.swing.JPanel;

import okuken.iste.controller.Controller;
import okuken.iste.logic.ConfigLogic;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JLabel;

public class TestPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public TestPanel() {

		JButton test1Button = new JButton("test1");
		test1Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().test1();
			}
		});

		JLabel test2Label = new JLabel(ConfigLogic.getInstance().getProcessOptions().getProjectDto().toString());

		JButton test2Button = new JButton("test2");
		test2Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				test2Label.setText(ConfigLogic.getInstance().getProcessOptions().getProjectDto().toString());
			}
		});

		add(test1Button);

		add(test2Label);
		add(test2Button);

	}

}
