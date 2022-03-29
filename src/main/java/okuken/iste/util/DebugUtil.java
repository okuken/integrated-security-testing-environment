package okuken.iste.util;

import java.awt.Component;
import java.awt.Container;

public class DebugUtil {

	public static void printComponentTree(Component component) {
		printComponentTreeImpl(component, "");
	}
	private static void printComponentTreeImpl(Component component, String level) {
		System.out.println(level + component);
		if(component instanceof Container) {
			for(var childComponent: ((Container)component).getComponents()) {
				printComponentTreeImpl(childComponent, level + " "); //recursive
			}
		}
	}

}
