package okuken.iste.util;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ThreadUtil {

	private static final ExecutorService executorService = Executors.newCachedThreadPool();

	public static void submit(Runnable task) {
		executorService.submit(task);
	}

	public static void shutdownExecutorService() {
		try {
			executorService.shutdownNow();
		} catch(Exception e) {
			BurpUtil.printEventLog(e.getMessage());
		}
	}

}
