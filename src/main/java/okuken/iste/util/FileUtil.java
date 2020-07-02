package okuken.iste.util;

import java.io.File;

import javax.swing.JFileChooser;

public class FileUtil {

	public static JFileChooser createSingleFileChooser(String title) {
		JFileChooser ret = new JFileChooser();
		ret.setDialogTitle(title);
		ret.setCurrentDirectory(new File(System.getProperty("user.home")));
		ret.setFileSelectionMode(JFileChooser.FILES_ONLY);
		ret.setMultiSelectionEnabled(false);
		return ret;
	}

}
