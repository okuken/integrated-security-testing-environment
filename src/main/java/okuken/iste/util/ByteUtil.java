package okuken.iste.util;

public class ByteUtil {

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

}
