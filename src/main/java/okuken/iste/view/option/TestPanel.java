package okuken.iste.view.option;

import javax.swing.JPanel;

import okuken.iste.controller.Controller;

import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class TestPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public TestPanel() {
		
		JButton test1Button = new JButton("test1");
		test1Button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().test1();
			}
		});
		add(test1Button);

	}

}
