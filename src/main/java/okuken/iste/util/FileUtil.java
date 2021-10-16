package okuken.iste.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

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

	public static String read(File file) {
		try {
			return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static void write(File file, String content) {
		try (FileOutputStream fos = new FileOutputStream(file);
				OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
				BufferedWriter bw = new BufferedWriter(osw)) {

			bw.write(content);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
