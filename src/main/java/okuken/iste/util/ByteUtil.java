package okuken.iste.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.mozilla.universalchardet.UniversalDetector;

public class ByteUtil {

	public static final Charset DEFAULT_SINGLE_BYTE_CHARSET = StandardCharsets.ISO_8859_1;

	public static byte[] remove(byte[] target, int removeIndex) {
		byte[] ret = new byte[target.length - 1];
		for(int i = 0, j = 0; i < target.length; i++, j++) {
			if(i == removeIndex) {
				i++;
				if(i >= target.length) {
					break;
				}
			}
			ret[j] = target[i];
		}
		return ret;
	}

	public static byte[] replace(byte[] target, int startIndex, int endIndex, String asciiStr) {
		var targetStr = new String(target, DEFAULT_SINGLE_BYTE_CHARSET);
		return new StringBuilder()
			.append(targetStr.substring(0, startIndex))
			.append(asciiStr)
			.append(targetStr.substring(endIndex))
			.toString()
			.getBytes(ByteUtil.DEFAULT_SINGLE_BYTE_CHARSET);
	}

	public static int endIndexOf(byte[] target, byte[] targetBreak, byte[] searchStart, byte[] searchEnd) {
		for(int i = 0; i < target.length; i++) {
			if(judgeMatch(target, i, targetBreak)) {
				return -1;
			}
			if(judgeMatch(target, i, searchStart)) {
				int currentIndex = i + searchStart.length;
				for(int j = 0; currentIndex + j < target.length; j++) {
					if(judgeMatch(target, currentIndex + j, searchEnd)) {
						return currentIndex + j - 1;
					}
					if(judgeMatch(target, currentIndex + j, targetBreak)) {
						return -1;
					}
				}
			}
		}
		return -1;
	}
	private static boolean judgeMatch(byte[] targetBytes, int currentIndex, byte[] searchBytes) {
		if(currentIndex + searchBytes.length > targetBytes.length) {
			return false;
		}

		for(int i = 0; i < searchBytes.length; i++) {
			if(targetBytes[currentIndex + i] != searchBytes[i]) {
				return false;
			}
		}
		return true;
	}

	public static Charset detectEncoding(byte[] bytes) {
		try {
			var is = new ByteArrayInputStream(bytes);
			var buf = new byte[4096];
			var detector = new UniversalDetector(null);
			int nread;
			while ((nread = is.read(buf)) > 0 && !detector.isDone()) {
				detector.handleData(buf, 0, nread);
			}
			detector.dataEnd();

			String encoding = detector.getDetectedCharset();
			if(encoding == null) {
				return null;
			}

			return Charset.forName(encoding);

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
