package okuken.iste.view.common;

import javax.swing.JPanel;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

public class VerticalFlowPanel extends JPanel {

	private static final long serialVersionUID = 1L;

	private GridBagLayout gbl;
	private GridBagConstraints gbc;

	public VerticalFlowPanel() {
		gbl = new GridBagLayout();
		gbl.columnWeights = new double[]{Double.MIN_VALUE};
		setLayout(gbl);
		
		gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = new Insets(0, 5, 5, 5);
		
	}

	public void setAlignLeft() {
		gbc.anchor = GridBagConstraints.WEST;
	}

	@Override
	public Component add(Component comp) {
		gbl.setConstraints(comp, gbc);
		return super.add(comp);
	}

}
