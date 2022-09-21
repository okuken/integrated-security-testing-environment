package okuken.iste.util;

import java.awt.Component;
import java.awt.Container;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class DebugUtil {

	public static void printComponentTree(Component component) {
		printComponentTreeImpl(component, 0);
	}
	private static void printComponentTreeImpl(Component component, int level) {
		printComponent(component, level);
		if(component instanceof Container) {
			for(var childComponent: ((Container)component).getComponents()) {
				printComponentTreeImpl(childComponent, level + 1); //recursive
			}
		}
	}
	private static void printComponent(Component component, int level) {
		var levelIndent = IntStream.range(0, level).mapToObj(i -> " ").collect(Collectors.joining());
		System.out.println(levelIndent + component);
	}

}
