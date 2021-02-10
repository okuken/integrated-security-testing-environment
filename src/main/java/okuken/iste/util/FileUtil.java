package okuken.iste.util;

import java.io.File;

import javax.swing.JFileChooser;

public class FileUtil {

	public static JFileChooser createSingleFileChooser(String title) {
		return createSingleFileChooser(title, new File(System.getProperty("user.home")));
	}

	public static JFileChooser createSingleFileChooser(String title, String selectedFilePath) {
		return createSingleFileChooser(title, new File(selectedFilePath));
	}

	public static JFileChooser createSingleFileChooser(String title, File selectedFile) {
		JFileChooser ret = new JFileChooser();
		ret.setFileSelectionMode(JFileChooser.FILES_ONLY);
		ret.setMultiSelectionEnabled(false);
		ret.setDialogTitle(title);

		if(selectedFile.isDirectory()) {
			ret.setCurrentDirectory(selectedFile);
		} else {
			ret.setSelectedFile(selectedFile);
		}

		return ret;
	}

}
