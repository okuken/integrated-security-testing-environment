package okuken.iste.view.header;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import okuken.iste.consts.Captions;
import okuken.iste.controller.Controller;
import okuken.iste.util.BurpUtil;

import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class MainHeaderPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	public MainHeaderPanel() {
		FlowLayout flowLayout = (FlowLayout) getLayout();
		flowLayout.setAlignment(FlowLayout.RIGHT);
		
		JButton dockoutButton = new JButton(Captions.MAIN_HEADER_BUTTON_DOCKOUT);
		MainHeaderPanel that = this;
		dockoutButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(SwingUtilities.getWindowAncestor(that) == BurpUtil.getBurpSuiteJFrame()) {
					dockout();
				} else {
					dockin();
				}
			}
		});
		
		JButton initColumnWidthButton = new JButton(Captions.MAIN_HEADER_BUTTON_INIT_COLUMN_WIDTH);
		initColumnWidthButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Controller.getInstance().initMessageTableColumnWidth();
			}
		});
		add(initColumnWidthButton);
		add(dockoutButton);
	}

	private void dockout() {
		JFrame burpSuiteFrame = BurpUtil.getBurpSuiteJFrame();
		SwingUtilities.invokeLater(() -> {
			JFrame dockoutFrame = new JFrame();
			Controller.getInstance().setDockoutFrame(dockoutFrame);

			dockoutFrame.setTitle(Captions.TAB_SUITE);
			dockoutFrame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
			dockoutFrame.setBounds(burpSuiteFrame.getBounds());
			dockoutFrame.setContentPane(Controller.getInstance().getMainPanel());
			dockoutFrame.setLocationRelativeTo(burpSuiteFrame);
			dockoutFrame.setVisible(true);
		});
	}

	private void dockin() {
		Controller controller = Controller.getInstance();
		controller.getMainTabbedPane().insertTab(Captions.TAB_MAIN, null, controller.getMainPanel(), null, 0);
		controller.disposeDockoutFrame();
	}

}
